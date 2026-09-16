rule TTP_XOR_MULT_DOSStub_32ac {
  strings:
    $key_32ac = { 66 c4 [2] 12 dc [2] 55 de [2] 12 cf [2] 5c c3 [2] 50 c9 [2] 47 c2 [2] 5c 8c [2] 61 }

  condition:
    any of them
}