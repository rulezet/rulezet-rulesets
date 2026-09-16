rule TTP_XOR_MULT_DOSStub_2baa {
  strings:
    $key_2baa = { 7f c2 [2] 0b da [2] 4c d8 [2] 0b c9 [2] 45 c5 [2] 49 cf [2] 5e c4 [2] 45 8a [2] 78 }

  condition:
    any of them
}