rule TTP_XOR_MULT_DOSStub_61b6 {
  strings:
    $key_61b6 = { 35 de [2] 41 c6 [2] 06 c4 [2] 41 d5 [2] 0f d9 [2] 03 d3 [2] 14 d8 [2] 0f 96 [2] 32 }

  condition:
    any of them
}