rule TTP_XOR_MULT_DOSStub_abd3 {
  strings:
    $key_abd3 = { ff bb [2] 8b a3 [2] cc a1 [2] 8b b0 [2] c5 bc [2] c9 b6 [2] de bd [2] c5 f3 [2] f8 }

  condition:
    any of them
}