rule TTP_XOR_MULT_DOSStub_0db6 {
  strings:
    $key_0db6 = { 59 de [2] 2d c6 [2] 6a c4 [2] 2d d5 [2] 63 d9 [2] 6f d3 [2] 78 d8 [2] 63 96 [2] 5e }

  condition:
    any of them
}