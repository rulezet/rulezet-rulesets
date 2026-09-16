rule TTP_XOR_MULT_DOSStub_66b6 {
  strings:
    $key_66b6 = { 32 de [2] 46 c6 [2] 01 c4 [2] 46 d5 [2] 08 d9 [2] 04 d3 [2] 13 d8 [2] 08 96 [2] 35 }

  condition:
    any of them
}