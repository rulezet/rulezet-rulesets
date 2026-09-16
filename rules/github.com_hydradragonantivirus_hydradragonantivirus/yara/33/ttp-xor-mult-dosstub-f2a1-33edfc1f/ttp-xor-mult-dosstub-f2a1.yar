rule TTP_XOR_MULT_DOSStub_f2a1 {
  strings:
    $key_f2a1 = { a6 c9 [2] d2 d1 [2] 95 d3 [2] d2 c2 [2] 9c ce [2] 90 c4 [2] 87 cf [2] 9c 81 [2] a1 }

  condition:
    any of them
}