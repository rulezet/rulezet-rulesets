rule TTP_XOR_MULT_DOSStub_38ac {
  strings:
    $key_38ac = { 6c c4 [2] 18 dc [2] 5f de [2] 18 cf [2] 56 c3 [2] 5a c9 [2] 4d c2 [2] 56 8c [2] 6b }

  condition:
    any of them
}