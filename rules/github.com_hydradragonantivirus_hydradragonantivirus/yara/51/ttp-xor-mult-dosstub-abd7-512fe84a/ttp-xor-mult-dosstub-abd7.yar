rule TTP_XOR_MULT_DOSStub_abd7 {
  strings:
    $key_abd7 = { ff bf [2] 8b a7 [2] cc a5 [2] 8b b4 [2] c5 b8 [2] c9 b2 [2] de b9 [2] c5 f7 [2] f8 }

  condition:
    any of them
}