rule TTP_XOR_MULT_DOSStub_26ac {
  strings:
    $key_26ac = { 72 c4 [2] 06 dc [2] 41 de [2] 06 cf [2] 48 c3 [2] 44 c9 [2] 53 c2 [2] 48 8c [2] 75 }

  condition:
    any of them
}