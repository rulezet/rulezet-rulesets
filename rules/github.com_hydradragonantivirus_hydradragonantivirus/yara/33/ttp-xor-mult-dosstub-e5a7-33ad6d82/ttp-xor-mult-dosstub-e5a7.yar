rule TTP_XOR_MULT_DOSStub_e5a7 {
  strings:
    $key_e5a7 = { b1 cf [2] c5 d7 [2] 82 d5 [2] c5 c4 [2] 8b c8 [2] 87 c2 [2] 90 c9 [2] 8b 87 [2] b6 }

  condition:
    any of them
}