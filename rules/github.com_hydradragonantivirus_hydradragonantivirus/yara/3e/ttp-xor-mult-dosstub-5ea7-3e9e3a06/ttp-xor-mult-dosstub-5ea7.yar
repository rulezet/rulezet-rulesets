rule TTP_XOR_MULT_DOSStub_5ea7 {
  strings:
    $key_5ea7 = { 0a cf [2] 7e d7 [2] 39 d5 [2] 7e c4 [2] 30 c8 [2] 3c c2 [2] 2b c9 [2] 30 87 [2] 0d }

  condition:
    any of them
}