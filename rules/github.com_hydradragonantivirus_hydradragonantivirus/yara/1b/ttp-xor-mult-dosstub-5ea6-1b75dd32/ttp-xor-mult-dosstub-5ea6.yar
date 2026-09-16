rule TTP_XOR_MULT_DOSStub_5ea6 {
  strings:
    $key_5ea6 = { 0a ce [2] 7e d6 [2] 39 d4 [2] 7e c5 [2] 30 c9 [2] 3c c3 [2] 2b c8 [2] 30 86 [2] 0d }

  condition:
    any of them
}