rule TTP_XOR_MULT_DOSStub_90d2 {
  strings:
    $key_90d2 = { c4 ba [2] b0 a2 [2] f7 a0 [2] b0 b1 [2] fe bd [2] f2 b7 [2] e5 bc [2] fe f2 [2] c3 }

  condition:
    any of them
}