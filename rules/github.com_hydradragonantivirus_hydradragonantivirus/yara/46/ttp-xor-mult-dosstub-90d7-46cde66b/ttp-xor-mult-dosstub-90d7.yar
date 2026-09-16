rule TTP_XOR_MULT_DOSStub_90d7 {
  strings:
    $key_90d7 = { c4 bf [2] b0 a7 [2] f7 a5 [2] b0 b4 [2] fe b8 [2] f2 b2 [2] e5 b9 [2] fe f7 [2] c3 }

  condition:
    any of them
}