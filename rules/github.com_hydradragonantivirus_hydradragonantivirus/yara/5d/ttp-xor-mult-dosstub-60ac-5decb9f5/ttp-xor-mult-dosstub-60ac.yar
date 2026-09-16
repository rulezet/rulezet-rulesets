rule TTP_XOR_MULT_DOSStub_60ac {
  strings:
    $key_60ac = { 34 c4 [2] 40 dc [2] 07 de [2] 40 cf [2] 0e c3 [2] 02 c9 [2] 15 c2 [2] 0e 8c [2] 33 }

  condition:
    any of them
}