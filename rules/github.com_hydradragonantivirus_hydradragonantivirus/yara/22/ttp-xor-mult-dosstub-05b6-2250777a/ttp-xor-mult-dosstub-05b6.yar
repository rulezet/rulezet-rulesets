rule TTP_XOR_MULT_DOSStub_05b6 {
  strings:
    $key_05b6 = { 51 de [2] 25 c6 [2] 62 c4 [2] 25 d5 [2] 6b d9 [2] 67 d3 [2] 70 d8 [2] 6b 96 [2] 56 }

  condition:
    any of them
}