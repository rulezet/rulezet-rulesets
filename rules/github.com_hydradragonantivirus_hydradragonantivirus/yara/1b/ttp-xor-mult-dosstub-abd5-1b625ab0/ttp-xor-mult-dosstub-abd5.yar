rule TTP_XOR_MULT_DOSStub_abd5 {
  strings:
    $key_abd5 = { ff bd [2] 8b a5 [2] cc a7 [2] 8b b6 [2] c5 ba [2] c9 b0 [2] de bb [2] c5 f5 [2] f8 }

  condition:
    any of them
}