rule TTP_XOR_MULT_DOSStub_33a7 {
  strings:
    $key_33a7 = { 67 cf [2] 13 d7 [2] 54 d5 [2] 13 c4 [2] 5d c8 [2] 51 c2 [2] 46 c9 [2] 5d 87 [2] 60 }

  condition:
    any of them
}