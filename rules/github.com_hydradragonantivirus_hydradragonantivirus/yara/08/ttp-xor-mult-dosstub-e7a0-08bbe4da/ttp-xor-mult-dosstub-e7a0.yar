rule TTP_XOR_MULT_DOSStub_e7a0 {
  strings:
    $key_e7a0 = { b3 c8 [2] c7 d0 [2] 80 d2 [2] c7 c3 [2] 89 cf [2] 85 c5 [2] 92 ce [2] 89 80 [2] b4 }

  condition:
    any of them
}