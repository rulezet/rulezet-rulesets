rule TTP_XOR_MULT_DOSStub_e1a0 {
  strings:
    $key_e1a0 = { b5 c8 [2] c1 d0 [2] 86 d2 [2] c1 c3 [2] 8f cf [2] 83 c5 [2] 94 ce [2] 8f 80 [2] b2 }

  condition:
    any of them
}