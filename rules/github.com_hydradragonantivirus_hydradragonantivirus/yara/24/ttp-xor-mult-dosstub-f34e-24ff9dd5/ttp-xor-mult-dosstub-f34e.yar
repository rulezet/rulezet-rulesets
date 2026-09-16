rule TTP_XOR_MULT_DOSStub_f34e {
  strings:
    $key_f34e = { a7 26 [2] d3 3e [2] 94 3c [2] d3 2d [2] 9d 21 [2] 91 2b [2] 86 20 [2] 9d 6e [2] a0 }

  condition:
    any of them
}