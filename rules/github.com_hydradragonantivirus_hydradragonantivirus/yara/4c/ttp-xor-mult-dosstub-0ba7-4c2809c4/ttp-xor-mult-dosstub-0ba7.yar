rule TTP_XOR_MULT_DOSStub_0ba7 {
  strings:
    $key_0ba7 = { 5f cf [2] 2b d7 [2] 6c d5 [2] 2b c4 [2] 65 c8 [2] 69 c2 [2] 7e c9 [2] 65 87 [2] 58 }

  condition:
    any of them
}