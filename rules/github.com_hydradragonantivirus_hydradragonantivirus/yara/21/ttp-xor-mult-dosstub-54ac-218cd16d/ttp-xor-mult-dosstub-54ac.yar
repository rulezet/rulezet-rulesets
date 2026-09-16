rule TTP_XOR_MULT_DOSStub_54ac {
  strings:
    $key_54ac = { 00 c4 [2] 74 dc [2] 33 de [2] 74 cf [2] 3a c3 [2] 36 c9 [2] 21 c2 [2] 3a 8c [2] 07 }

  condition:
    any of them
}