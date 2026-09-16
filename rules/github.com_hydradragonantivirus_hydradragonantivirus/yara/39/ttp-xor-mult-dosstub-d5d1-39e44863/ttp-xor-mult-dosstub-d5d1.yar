rule TTP_XOR_MULT_DOSStub_d5d1 {
  strings:
    $key_d5d1 = { 81 b9 [2] f5 a1 [2] b2 a3 [2] f5 b2 [2] bb be [2] b7 b4 [2] a0 bf [2] bb f1 [2] 86 }

  condition:
    any of them
}