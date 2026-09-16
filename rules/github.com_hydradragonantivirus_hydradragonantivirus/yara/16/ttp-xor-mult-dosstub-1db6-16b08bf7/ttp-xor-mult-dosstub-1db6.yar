rule TTP_XOR_MULT_DOSStub_1db6 {
  strings:
    $key_1db6 = { 49 de [2] 3d c6 [2] 7a c4 [2] 3d d5 [2] 73 d9 [2] 7f d3 [2] 68 d8 [2] 73 96 [2] 4e }

  condition:
    any of them
}