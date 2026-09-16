rule TTP_XOR_MULT_DOSStub_45ac {
  strings:
    $key_45ac = { 11 c4 [2] 65 dc [2] 22 de [2] 65 cf [2] 2b c3 [2] 27 c9 [2] 30 c2 [2] 2b 8c [2] 16 }

  condition:
    any of them
}