rule TTP_XOR_MULT_DOSStub_6bb6 {
  strings:
    $key_6bb6 = { 3f de [2] 4b c6 [2] 0c c4 [2] 4b d5 [2] 05 d9 [2] 09 d3 [2] 1e d8 [2] 05 96 [2] 38 }

  condition:
    any of them
}