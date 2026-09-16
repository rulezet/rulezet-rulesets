rule TTP_XOR_MULT_DOSStub_15ac {
  strings:
    $key_15ac = { 41 c4 [2] 35 dc [2] 72 de [2] 35 cf [2] 7b c3 [2] 77 c9 [2] 60 c2 [2] 7b 8c [2] 46 }

  condition:
    any of them
}