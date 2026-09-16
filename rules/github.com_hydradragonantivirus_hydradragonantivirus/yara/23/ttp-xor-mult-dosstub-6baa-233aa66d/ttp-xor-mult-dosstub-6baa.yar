rule TTP_XOR_MULT_DOSStub_6baa {
  strings:
    $key_6baa = { 3f c2 [2] 4b da [2] 0c d8 [2] 4b c9 [2] 05 c5 [2] 09 cf [2] 1e c4 [2] 05 8a [2] 38 }

  condition:
    any of them
}