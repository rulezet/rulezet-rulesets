rule TTP_XOR_MULT_DOSStub_23ac {
  strings:
    $key_23ac = { 77 c4 [2] 03 dc [2] 44 de [2] 03 cf [2] 4d c3 [2] 41 c9 [2] 56 c2 [2] 4d 8c [2] 70 }

  condition:
    any of them
}