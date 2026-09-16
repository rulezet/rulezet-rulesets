rule TTP_XOR_MULT_DOSStub_43a1 {
  strings:
    $key_43a1 = { 17 c9 [2] 63 d1 [2] 24 d3 [2] 63 c2 [2] 2d ce [2] 21 c4 [2] 36 cf [2] 2d 81 [2] 10 }

  condition:
    any of them
}