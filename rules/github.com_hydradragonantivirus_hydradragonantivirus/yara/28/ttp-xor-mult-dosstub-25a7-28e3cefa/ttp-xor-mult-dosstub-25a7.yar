rule TTP_XOR_MULT_DOSStub_25a7 {
  strings:
    $key_25a7 = { 71 cf [2] 05 d7 [2] 42 d5 [2] 05 c4 [2] 4b c8 [2] 47 c2 [2] 50 c9 [2] 4b 87 [2] 76 }

  condition:
    any of them
}