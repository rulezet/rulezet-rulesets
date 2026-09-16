rule TTP_XOR_MULT_DOSStub_7ba7 {
  strings:
    $key_7ba7 = { 2f cf [2] 5b d7 [2] 1c d5 [2] 5b c4 [2] 15 c8 [2] 19 c2 [2] 0e c9 [2] 15 87 [2] 28 }

  condition:
    any of them
}