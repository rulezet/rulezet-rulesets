rule TTP_XOR_MULT_DOSStub_4ea7 {
  strings:
    $key_4ea7 = { 1a cf [2] 6e d7 [2] 29 d5 [2] 6e c4 [2] 20 c8 [2] 2c c2 [2] 3b c9 [2] 20 87 [2] 1d }

  condition:
    any of them
}