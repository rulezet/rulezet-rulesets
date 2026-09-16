rule TTP_XOR_MULT_DOSStub_00ac {
  strings:
    $key_00ac = { 54 c4 [2] 20 dc [2] 67 de [2] 20 cf [2] 6e c3 [2] 62 c9 [2] 75 c2 [2] 6e 8c [2] 53 }

  condition:
    any of them
}