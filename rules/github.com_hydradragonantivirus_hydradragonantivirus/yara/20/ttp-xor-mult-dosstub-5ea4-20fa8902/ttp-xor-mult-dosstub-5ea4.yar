rule TTP_XOR_MULT_DOSStub_5ea4 {
  strings:
    $key_5ea4 = { 0a cc [2] 7e d4 [2] 39 d6 [2] 7e c7 [2] 30 cb [2] 3c c1 [2] 2b ca [2] 30 84 [2] 0d }

  condition:
    any of them
}