rule TTP_XOR_MULT_DOSStub_e1ac {
  strings:
    $key_e1ac = { b5 c4 [2] c1 dc [2] 86 de [2] c1 cf [2] 8f c3 [2] 83 c9 [2] 94 c2 [2] 8f 8c [2] b2 }

  condition:
    any of them
}