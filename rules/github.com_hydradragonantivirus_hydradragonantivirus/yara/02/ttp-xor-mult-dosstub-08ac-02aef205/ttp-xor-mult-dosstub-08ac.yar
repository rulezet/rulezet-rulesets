rule TTP_XOR_MULT_DOSStub_08ac {
  strings:
    $key_08ac = { 5c c4 [2] 28 dc [2] 6f de [2] 28 cf [2] 66 c3 [2] 6a c9 [2] 7d c2 [2] 66 8c [2] 5b }

  condition:
    any of them
}