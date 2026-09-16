rule TTP_XOR_MULT_DOSStub_39a7 {
  strings:
    $key_39a7 = { 6d cf [2] 19 d7 [2] 5e d5 [2] 19 c4 [2] 57 c8 [2] 5b c2 [2] 4c c9 [2] 57 87 [2] 6a }

  condition:
    any of them
}