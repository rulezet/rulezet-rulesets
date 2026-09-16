rule TTP_XOR_MULT_DOSStub_20ac {
  strings:
    $key_20ac = { 74 c4 [2] 00 dc [2] 47 de [2] 00 cf [2] 4e c3 [2] 42 c9 [2] 55 c2 [2] 4e 8c [2] 73 }

  condition:
    any of them
}