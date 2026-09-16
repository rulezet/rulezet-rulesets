rule TTP_XOR_MULT_DOSStub_f37e {
  strings:
    $key_f37e = { a7 16 [2] d3 0e [2] 94 0c [2] d3 1d [2] 9d 11 [2] 91 1b [2] 86 10 [2] 9d 5e [2] a0 }

  condition:
    any of them
}