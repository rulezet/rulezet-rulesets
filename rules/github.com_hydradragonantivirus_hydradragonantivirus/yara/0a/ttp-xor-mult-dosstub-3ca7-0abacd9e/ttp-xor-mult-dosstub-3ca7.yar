rule TTP_XOR_MULT_DOSStub_3ca7 {
  strings:
    $key_3ca7 = { 68 cf [2] 1c d7 [2] 5b d5 [2] 1c c4 [2] 52 c8 [2] 5e c2 [2] 49 c9 [2] 52 87 [2] 6f }

  condition:
    any of them
}