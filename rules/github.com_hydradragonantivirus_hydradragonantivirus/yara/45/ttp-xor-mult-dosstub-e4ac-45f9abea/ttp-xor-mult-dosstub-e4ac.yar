rule TTP_XOR_MULT_DOSStub_e4ac {
  strings:
    $key_e4ac = { b0 c4 [2] c4 dc [2] 83 de [2] c4 cf [2] 8a c3 [2] 86 c9 [2] 91 c2 [2] 8a 8c [2] b7 }

  condition:
    any of them
}