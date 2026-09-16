rule TTP_XOR_MULT_DOSStub_6ca7 {
  strings:
    $key_6ca7 = { 38 cf [2] 4c d7 [2] 0b d5 [2] 4c c4 [2] 02 c8 [2] 0e c2 [2] 19 c9 [2] 02 87 [2] 3f }

  condition:
    any of them
}