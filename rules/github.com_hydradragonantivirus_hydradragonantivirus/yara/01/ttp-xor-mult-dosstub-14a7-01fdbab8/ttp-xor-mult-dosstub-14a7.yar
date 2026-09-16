rule TTP_XOR_MULT_DOSStub_14a7 {
  strings:
    $key_14a7 = { 40 cf [2] 34 d7 [2] 73 d5 [2] 34 c4 [2] 7a c8 [2] 76 c2 [2] 61 c9 [2] 7a 87 [2] 47 }

  condition:
    any of them
}