rule TTP_XOR_MULT_DOSStub_e7ac {
  strings:
    $key_e7ac = { b3 c4 [2] c7 dc [2] 80 de [2] c7 cf [2] 89 c3 [2] 85 c9 [2] 92 c2 [2] 89 8c [2] b4 }

  condition:
    any of them
}