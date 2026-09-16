rule TTP_XOR_MULT_DOSStub_67a7 {
  strings:
    $key_67a7 = { 33 cf [2] 47 d7 [2] 00 d5 [2] 47 c4 [2] 09 c8 [2] 05 c2 [2] 12 c9 [2] 09 87 [2] 34 }

  condition:
    any of them
}