rule TTP_XOR_MULT_DOSStub_01a7 {
  strings:
    $key_01a7 = { 55 cf [2] 21 d7 [2] 66 d5 [2] 21 c4 [2] 6f c8 [2] 63 c2 [2] 74 c9 [2] 6f 87 [2] 52 }

  condition:
    any of them
}