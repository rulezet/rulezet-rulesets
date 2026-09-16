rule TTP_XOR_MULT_DOSStub_14ac {
  strings:
    $key_14ac = { 40 c4 [2] 34 dc [2] 73 de [2] 34 cf [2] 7a c3 [2] 76 c9 [2] 61 c2 [2] 7a 8c [2] 47 }

  condition:
    any of them
}