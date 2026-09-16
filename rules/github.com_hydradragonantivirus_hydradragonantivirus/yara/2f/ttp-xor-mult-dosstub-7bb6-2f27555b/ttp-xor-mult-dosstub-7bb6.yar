rule TTP_XOR_MULT_DOSStub_7bb6 {
  strings:
    $key_7bb6 = { 2f de [2] 5b c6 [2] 1c c4 [2] 5b d5 [2] 15 d9 [2] 19 d3 [2] 0e d8 [2] 15 96 [2] 28 }

  condition:
    any of them
}