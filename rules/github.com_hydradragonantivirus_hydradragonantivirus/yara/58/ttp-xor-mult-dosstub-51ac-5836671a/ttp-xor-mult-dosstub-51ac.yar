rule TTP_XOR_MULT_DOSStub_51ac {
  strings:
    $key_51ac = { 05 c4 [2] 71 dc [2] 36 de [2] 71 cf [2] 3f c3 [2] 33 c9 [2] 24 c2 [2] 3f 8c [2] 02 }

  condition:
    any of them
}