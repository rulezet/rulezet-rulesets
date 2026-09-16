rule TTP_XOR_MULT_DOSStub_e6a0 {
  strings:
    $key_e6a0 = { b2 c8 [2] c6 d0 [2] 81 d2 [2] c6 c3 [2] 88 cf [2] 84 c5 [2] 93 ce [2] 88 80 [2] b5 }

  condition:
    any of them
}