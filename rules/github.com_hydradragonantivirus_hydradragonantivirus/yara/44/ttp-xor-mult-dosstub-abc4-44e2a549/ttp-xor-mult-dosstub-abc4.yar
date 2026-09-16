rule TTP_XOR_MULT_DOSStub_abc4 {
  strings:
    $key_abc4 = { ff ac [2] 8b b4 [2] cc b6 [2] 8b a7 [2] c5 ab [2] c9 a1 [2] de aa [2] c5 e4 [2] f8 }

  condition:
    any of them
}