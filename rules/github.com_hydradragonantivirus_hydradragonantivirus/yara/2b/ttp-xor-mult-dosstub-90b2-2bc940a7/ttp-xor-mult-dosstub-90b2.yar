rule TTP_XOR_MULT_DOSStub_90b2 {
  strings:
    $key_90b2 = { c4 da [2] b0 c2 [2] f7 c0 [2] b0 d1 [2] fe dd [2] f2 d7 [2] e5 dc [2] fe 92 [2] c3 }

  condition:
    any of them
}