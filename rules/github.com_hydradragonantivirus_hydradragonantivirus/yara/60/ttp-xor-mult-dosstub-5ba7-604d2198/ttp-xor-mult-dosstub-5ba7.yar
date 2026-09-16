rule TTP_XOR_MULT_DOSStub_5ba7 {
  strings:
    $key_5ba7 = { 0f cf [2] 7b d7 [2] 3c d5 [2] 7b c4 [2] 35 c8 [2] 39 c2 [2] 2e c9 [2] 35 87 [2] 08 }

  condition:
    any of them
}