rule TTP_XOR_MULT_DOSStub_6ba7 {
  strings:
    $key_6ba7 = { 3f cf [2] 4b d7 [2] 0c d5 [2] 4b c4 [2] 05 c8 [2] 09 c2 [2] 1e c9 [2] 05 87 [2] 38 }

  condition:
    any of them
}