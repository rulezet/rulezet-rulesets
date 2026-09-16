rule TTP_XOR_MULT_DOSStub_1ea6 {
  strings:
    $key_1ea6 = { 4a ce [2] 3e d6 [2] 79 d4 [2] 3e c5 [2] 70 c9 [2] 7c c3 [2] 6b c8 [2] 70 86 [2] 4d }

  condition:
    any of them
}