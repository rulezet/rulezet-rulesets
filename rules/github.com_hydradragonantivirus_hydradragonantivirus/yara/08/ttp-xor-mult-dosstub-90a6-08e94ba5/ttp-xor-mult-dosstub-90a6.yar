rule TTP_XOR_MULT_DOSStub_90a6 {
  strings:
    $key_90a6 = { c4 ce [2] b0 d6 [2] f7 d4 [2] b0 c5 [2] fe c9 [2] f2 c3 [2] e5 c8 [2] fe 86 [2] c3 }

  condition:
    any of them
}