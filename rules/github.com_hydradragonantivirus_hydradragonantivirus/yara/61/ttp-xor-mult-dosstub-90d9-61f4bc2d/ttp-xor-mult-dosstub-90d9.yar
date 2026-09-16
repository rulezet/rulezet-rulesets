rule TTP_XOR_MULT_DOSStub_90d9 {
  strings:
    $key_90d9 = { c4 b1 [2] b0 a9 [2] f7 ab [2] b0 ba [2] fe b6 [2] f2 bc [2] e5 b7 [2] fe f9 [2] c3 }

  condition:
    any of them
}