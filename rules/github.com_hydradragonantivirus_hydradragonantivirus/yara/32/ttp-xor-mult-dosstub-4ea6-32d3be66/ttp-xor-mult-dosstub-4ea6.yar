rule TTP_XOR_MULT_DOSStub_4ea6 {
  strings:
    $key_4ea6 = { 1a ce [2] 6e d6 [2] 29 d4 [2] 6e c5 [2] 20 c9 [2] 2c c3 [2] 3b c8 [2] 20 86 [2] 1d }

  condition:
    any of them
}