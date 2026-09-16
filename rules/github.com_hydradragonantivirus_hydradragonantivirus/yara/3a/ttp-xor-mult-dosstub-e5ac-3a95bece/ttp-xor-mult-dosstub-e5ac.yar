rule TTP_XOR_MULT_DOSStub_e5ac {
  strings:
    $key_e5ac = { b1 c4 [2] c5 dc [2] 82 de [2] c5 cf [2] 8b c3 [2] 87 c9 [2] 90 c2 [2] 8b 8c [2] b6 }

  condition:
    any of them
}