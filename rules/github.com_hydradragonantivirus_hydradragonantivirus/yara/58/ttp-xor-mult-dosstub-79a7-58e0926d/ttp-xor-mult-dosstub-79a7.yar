rule TTP_XOR_MULT_DOSStub_79a7 {
  strings:
    $key_79a7 = { 2d cf [2] 59 d7 [2] 1e d5 [2] 59 c4 [2] 17 c8 [2] 1b c2 [2] 0c c9 [2] 17 87 [2] 2a }

  condition:
    any of them
}