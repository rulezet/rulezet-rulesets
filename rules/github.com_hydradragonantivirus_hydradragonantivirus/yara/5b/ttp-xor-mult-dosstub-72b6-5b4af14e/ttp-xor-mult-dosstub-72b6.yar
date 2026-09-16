rule TTP_XOR_MULT_DOSStub_72b6 {
  strings:
    $key_72b6 = { 26 de [2] 52 c6 [2] 15 c4 [2] 52 d5 [2] 1c d9 [2] 10 d3 [2] 07 d8 [2] 1c 96 [2] 21 }

  condition:
    any of them
}