rule TTP_XOR_MULT_DOSStub_2ea7 {
  strings:
    $key_2ea7 = { 7a cf [2] 0e d7 [2] 49 d5 [2] 0e c4 [2] 40 c8 [2] 4c c2 [2] 5b c9 [2] 40 87 [2] 7d }

  condition:
    any of them
}