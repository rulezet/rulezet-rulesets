rule TTP_XOR_MULT_DOSStub_36a1 {
  strings:
    $key_36a1 = { 62 c9 [2] 16 d1 [2] 51 d3 [2] 16 c2 [2] 58 ce [2] 54 c4 [2] 43 cf [2] 58 81 [2] 65 }

  condition:
    any of them
}