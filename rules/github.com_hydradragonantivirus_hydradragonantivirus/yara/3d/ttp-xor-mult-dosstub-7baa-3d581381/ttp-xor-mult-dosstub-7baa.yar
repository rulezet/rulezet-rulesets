rule TTP_XOR_MULT_DOSStub_7baa {
  strings:
    $key_7baa = { 2f c2 [2] 5b da [2] 1c d8 [2] 5b c9 [2] 15 c5 [2] 19 cf [2] 0e c4 [2] 15 8a [2] 28 }

  condition:
    any of them
}