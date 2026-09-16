rule TTP_XOR_MULT_DOSStub_3ea4 {
  strings:
    $key_3ea4 = { 6a cc [2] 1e d4 [2] 59 d6 [2] 1e c7 [2] 50 cb [2] 5c c1 [2] 4b ca [2] 50 84 [2] 6d }

  condition:
    any of them
}