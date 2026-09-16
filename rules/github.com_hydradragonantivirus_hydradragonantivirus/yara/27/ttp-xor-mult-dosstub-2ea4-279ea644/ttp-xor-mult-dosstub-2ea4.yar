rule TTP_XOR_MULT_DOSStub_2ea4 {
  strings:
    $key_2ea4 = { 7a cc [2] 0e d4 [2] 49 d6 [2] 0e c7 [2] 40 cb [2] 4c c1 [2] 5b ca [2] 40 84 [2] 7d }

  condition:
    any of them
}