rule TTP_XOR_MULT_DOSStub_c3a7 {
  strings:
    $key_c3a7 = { 97 cf [2] e3 d7 [2] a4 d5 [2] e3 c4 [2] ad c8 [2] a1 c2 [2] b6 c9 [2] ad 87 [2] 90 }

  condition:
    any of them
}