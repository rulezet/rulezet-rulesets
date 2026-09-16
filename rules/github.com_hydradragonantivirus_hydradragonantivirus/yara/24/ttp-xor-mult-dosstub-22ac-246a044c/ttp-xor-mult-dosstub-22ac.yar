rule TTP_XOR_MULT_DOSStub_22ac {
  strings:
    $key_22ac = { 76 c4 [2] 02 dc [2] 45 de [2] 02 cf [2] 4c c3 [2] 40 c9 [2] 57 c2 [2] 4c 8c [2] 71 }

  condition:
    any of them
}