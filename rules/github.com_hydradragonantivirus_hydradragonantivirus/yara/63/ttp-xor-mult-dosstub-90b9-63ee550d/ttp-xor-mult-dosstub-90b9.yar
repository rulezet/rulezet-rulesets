rule TTP_XOR_MULT_DOSStub_90b9 {
  strings:
    $key_90b9 = { c4 d1 [2] b0 c9 [2] f7 cb [2] b0 da [2] fe d6 [2] f2 dc [2] e5 d7 [2] fe 99 [2] c3 }

  condition:
    any of them
}