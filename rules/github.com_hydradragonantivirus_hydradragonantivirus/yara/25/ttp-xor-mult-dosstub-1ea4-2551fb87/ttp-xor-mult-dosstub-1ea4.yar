rule TTP_XOR_MULT_DOSStub_1ea4 {
  strings:
    $key_1ea4 = { 4a cc [2] 3e d4 [2] 79 d6 [2] 3e c7 [2] 70 cb [2] 7c c1 [2] 6b ca [2] 70 84 [2] 4d }

  condition:
    any of them
}