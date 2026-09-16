rule TTP_XOR_MULT_DOSStub_c3a1 {
  strings:
    $key_c3a1 = { 97 c9 [2] e3 d1 [2] a4 d3 [2] e3 c2 [2] ad ce [2] a1 c4 [2] b6 cf [2] ad 81 [2] 90 }

  condition:
    any of them
}