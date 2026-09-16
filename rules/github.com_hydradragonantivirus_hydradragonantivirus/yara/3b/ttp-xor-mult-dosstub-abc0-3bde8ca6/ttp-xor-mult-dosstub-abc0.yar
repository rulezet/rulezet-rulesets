rule TTP_XOR_MULT_DOSStub_abc0 {
  strings:
    $key_abc0 = { ff a8 [2] 8b b0 [2] cc b2 [2] 8b a3 [2] c5 af [2] c9 a5 [2] de ae [2] c5 e0 [2] f8 }

  condition:
    any of them
}