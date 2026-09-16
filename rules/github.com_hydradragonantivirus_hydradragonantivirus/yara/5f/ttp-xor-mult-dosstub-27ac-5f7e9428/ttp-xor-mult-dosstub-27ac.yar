rule TTP_XOR_MULT_DOSStub_27ac {
  strings:
    $key_27ac = { 73 c4 [2] 07 dc [2] 40 de [2] 07 cf [2] 49 c3 [2] 45 c9 [2] 52 c2 [2] 49 8c [2] 74 }

  condition:
    any of them
}