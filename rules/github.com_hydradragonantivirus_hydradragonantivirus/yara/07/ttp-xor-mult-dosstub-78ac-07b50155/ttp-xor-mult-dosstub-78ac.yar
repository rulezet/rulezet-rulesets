rule TTP_XOR_MULT_DOSStub_78ac {
  strings:
    $key_78ac = { 2c c4 [2] 58 dc [2] 1f de [2] 58 cf [2] 16 c3 [2] 1a c9 [2] 0d c2 [2] 16 8c [2] 2b }

  condition:
    any of them
}