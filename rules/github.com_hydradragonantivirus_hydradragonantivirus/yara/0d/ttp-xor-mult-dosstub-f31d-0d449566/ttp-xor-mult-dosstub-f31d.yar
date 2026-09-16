rule TTP_XOR_MULT_DOSStub_f31d {
  strings:
    $key_f31d = { a7 75 [2] d3 6d [2] 94 6f [2] d3 7e [2] 9d 72 [2] 91 78 [2] 86 73 [2] 9d 3d [2] a0 }

  condition:
    any of them
}