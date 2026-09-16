rule TTP_XOR_MULT_DOSStub_0ea4 {
  strings:
    $key_0ea4 = { 5a cc [2] 2e d4 [2] 69 d6 [2] 2e c7 [2] 60 cb [2] 6c c1 [2] 7b ca [2] 60 84 [2] 5d }

  condition:
    any of them
}