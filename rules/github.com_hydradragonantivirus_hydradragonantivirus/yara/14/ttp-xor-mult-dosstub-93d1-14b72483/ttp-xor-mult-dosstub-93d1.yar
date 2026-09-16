rule TTP_XOR_MULT_DOSStub_93d1 {
  strings:
    $key_93d1 = { c7 b9 [2] b3 a1 [2] f4 a3 [2] b3 b2 [2] fd be [2] f1 b4 [2] e6 bf [2] fd f1 [2] c0 }

  condition:
    any of them
}