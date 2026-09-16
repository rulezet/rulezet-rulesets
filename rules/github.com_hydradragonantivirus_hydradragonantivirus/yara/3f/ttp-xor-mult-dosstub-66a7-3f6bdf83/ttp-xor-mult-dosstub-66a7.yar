rule TTP_XOR_MULT_DOSStub_66a7 {
  strings:
    $key_66a7 = { 32 cf [2] 46 d7 [2] 01 d5 [2] 46 c4 [2] 08 c8 [2] 04 c2 [2] 13 c9 [2] 08 87 [2] 35 }

  condition:
    any of them
}