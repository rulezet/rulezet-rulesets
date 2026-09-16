rule TTP_XOR_MULT_DOSStub_0baa {
  strings:
    $key_0baa = { 5f c2 [2] 2b da [2] 6c d8 [2] 2b c9 [2] 65 c5 [2] 69 cf [2] 7e c4 [2] 65 8a [2] 58 }

  condition:
    any of them
}