rule TTP_XOR_MULT_DOSStub_01b6 {
  strings:
    $key_01b6 = { 55 de [2] 21 c6 [2] 66 c4 [2] 21 d5 [2] 6f d9 [2] 63 d3 [2] 74 d8 [2] 6f 96 [2] 52 }

  condition:
    any of them
}