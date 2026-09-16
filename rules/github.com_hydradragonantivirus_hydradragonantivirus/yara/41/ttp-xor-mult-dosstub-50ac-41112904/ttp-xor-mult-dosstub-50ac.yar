rule TTP_XOR_MULT_DOSStub_50ac {
  strings:
    $key_50ac = { 04 c4 [2] 70 dc [2] 37 de [2] 70 cf [2] 3e c3 [2] 32 c9 [2] 25 c2 [2] 3e 8c [2] 03 }

  condition:
    any of them
}