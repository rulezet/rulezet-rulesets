rule TTP_XOR_MULT_DOSStub_28ac {
  strings:
    $key_28ac = { 7c c4 [2] 08 dc [2] 4f de [2] 08 cf [2] 46 c3 [2] 4a c9 [2] 5d c2 [2] 46 8c [2] 7b }

  condition:
    any of them
}