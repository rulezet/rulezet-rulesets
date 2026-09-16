rule TTP_XOR_MULT_DOSStub_abd6 {
  strings:
    $key_abd6 = { ff be [2] 8b a6 [2] cc a4 [2] 8b b5 [2] c5 b9 [2] c9 b3 [2] de b8 [2] c5 f6 [2] f8 }

  condition:
    any of them
}