rule TTP_XOR_MULT_DOSStub_57ac {
  strings:
    $key_57ac = { 03 c4 [2] 77 dc [2] 30 de [2] 77 cf [2] 39 c3 [2] 35 c9 [2] 22 c2 [2] 39 8c [2] 04 }

  condition:
    any of them
}