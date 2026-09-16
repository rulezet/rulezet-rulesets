rule TTP_XOR_MULT_DOSStub_2ab6 {
  strings:
    $key_2ab6 = { 7e de [2] 0a c6 [2] 4d c4 [2] 0a d5 [2] 44 d9 [2] 48 d3 [2] 5f d8 [2] 44 96 [2] 79 }

  condition:
    any of them
}