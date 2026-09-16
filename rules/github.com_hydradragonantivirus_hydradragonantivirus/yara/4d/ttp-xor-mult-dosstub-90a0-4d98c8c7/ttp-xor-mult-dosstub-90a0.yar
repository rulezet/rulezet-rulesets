rule TTP_XOR_MULT_DOSStub_90a0 {
  strings:
    $key_90a0 = { c4 c8 [2] b0 d0 [2] f7 d2 [2] b0 c3 [2] fe cf [2] f2 c5 [2] e5 ce [2] fe 80 [2] c3 }

  condition:
    any of them
}