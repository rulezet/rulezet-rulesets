rule TTP_XOR_MULT_DOSStub_18ac {
  strings:
    $key_18ac = { 4c c4 [2] 38 dc [2] 7f de [2] 38 cf [2] 76 c3 [2] 7a c9 [2] 6d c2 [2] 76 8c [2] 4b }

  condition:
    any of them
}