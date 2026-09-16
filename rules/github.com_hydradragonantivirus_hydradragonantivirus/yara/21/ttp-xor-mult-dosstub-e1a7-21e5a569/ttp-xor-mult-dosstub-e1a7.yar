rule TTP_XOR_MULT_DOSStub_e1a7 {
  strings:
    $key_e1a7 = { b5 cf [2] c1 d7 [2] 86 d5 [2] c1 c4 [2] 8f c8 [2] 83 c2 [2] 94 c9 [2] 8f 87 [2] b2 }

  condition:
    any of them
}