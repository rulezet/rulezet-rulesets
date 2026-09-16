rule TTP_XOR_MULT_DOSStub_10a1 {
  strings:
    $key_10a1 = { 44 c9 [2] 30 d1 [2] 77 d3 [2] 30 c2 [2] 7e ce [2] 72 c4 [2] 65 cf [2] 7e 81 [2] 43 }

  condition:
    any of them
}