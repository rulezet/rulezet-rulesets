rule TTP_XOR_MULT_DOSStub_e4a0 {
  strings:
    $key_e4a0 = { b0 c8 [2] c4 d0 [2] 83 d2 [2] c4 c3 [2] 8a cf [2] 86 c5 [2] 91 ce [2] 8a 80 [2] b7 }

  condition:
    any of them
}