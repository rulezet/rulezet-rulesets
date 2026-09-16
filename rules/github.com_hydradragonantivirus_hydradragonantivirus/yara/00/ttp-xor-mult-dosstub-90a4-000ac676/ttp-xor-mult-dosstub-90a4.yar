rule TTP_XOR_MULT_DOSStub_90a4 {
  strings:
    $key_90a4 = { c4 cc [2] b0 d4 [2] f7 d6 [2] b0 c7 [2] fe cb [2] f2 c1 [2] e5 ca [2] fe 84 [2] c3 }

  condition:
    any of them
}