rule TTP_XOR_MULT_DOSStub_1baa {
  strings:
    $key_1baa = { 4f c2 [2] 3b da [2] 7c d8 [2] 3b c9 [2] 75 c5 [2] 79 cf [2] 6e c4 [2] 75 8a [2] 48 }

  condition:
    any of them
}