rule TTP_XOR_MULT_DOSStub_abc1 {
  strings:
    $key_abc1 = { ff a9 [2] 8b b1 [2] cc b3 [2] 8b a2 [2] c5 ae [2] c9 a4 [2] de af [2] c5 e1 [2] f8 }

  condition:
    any of them
}