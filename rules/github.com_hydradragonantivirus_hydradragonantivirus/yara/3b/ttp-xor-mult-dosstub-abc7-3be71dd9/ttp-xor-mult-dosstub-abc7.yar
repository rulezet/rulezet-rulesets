rule TTP_XOR_MULT_DOSStub_abc7 {
  strings:
    $key_abc7 = { ff af [2] 8b b7 [2] cc b5 [2] 8b a4 [2] c5 a8 [2] c9 a2 [2] de a9 [2] c5 e7 [2] f8 }

  condition:
    any of them
}