rule TTP_XOR_MULT_DOSStub_1ca7 {
  strings:
    $key_1ca7 = { 48 cf [2] 3c d7 [2] 7b d5 [2] 3c c4 [2] 72 c8 [2] 7e c2 [2] 69 c9 [2] 72 87 [2] 4f }

  condition:
    any of them
}