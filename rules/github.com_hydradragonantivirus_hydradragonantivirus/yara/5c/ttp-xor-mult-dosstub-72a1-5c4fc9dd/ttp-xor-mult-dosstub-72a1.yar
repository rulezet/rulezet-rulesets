rule TTP_XOR_MULT_DOSStub_72a1 {
  strings:
    $key_72a1 = { 26 c9 [2] 52 d1 [2] 15 d3 [2] 52 c2 [2] 1c ce [2] 10 c4 [2] 07 cf [2] 1c 81 [2] 21 }

  condition:
    any of them
}