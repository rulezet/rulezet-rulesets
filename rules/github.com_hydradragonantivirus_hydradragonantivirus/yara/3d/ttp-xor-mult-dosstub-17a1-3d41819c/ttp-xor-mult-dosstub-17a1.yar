rule TTP_XOR_MULT_DOSStub_17a1 {
  strings:
    $key_17a1 = { 43 c9 [2] 37 d1 [2] 70 d3 [2] 37 c2 [2] 79 ce [2] 75 c4 [2] 62 cf [2] 79 81 [2] 44 }

  condition:
    any of them
}