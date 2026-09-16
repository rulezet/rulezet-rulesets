rule TTP_XOR_MULT_DOSStub_e0ac {
  strings:
    $key_e0ac = { b4 c4 [2] c0 dc [2] 87 de [2] c0 cf [2] 8e c3 [2] 82 c9 [2] 95 c2 [2] 8e 8c [2] b3 }

  condition:
    any of them
}