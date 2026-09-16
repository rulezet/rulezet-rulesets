rule TTP_XOR_MULT_DOSStub_55ac {
  strings:
    $key_55ac = { 01 c4 [2] 75 dc [2] 32 de [2] 75 cf [2] 3b c3 [2] 37 c9 [2] 20 c2 [2] 3b 8c [2] 06 }

  condition:
    any of them
}