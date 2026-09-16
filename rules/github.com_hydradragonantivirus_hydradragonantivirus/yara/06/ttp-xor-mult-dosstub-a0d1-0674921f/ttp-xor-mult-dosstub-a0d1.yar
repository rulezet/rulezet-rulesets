rule TTP_XOR_MULT_DOSStub_a0d1 {
  strings:
    $key_a0d1 = { f4 b9 [2] 80 a1 [2] c7 a3 [2] 80 b2 [2] ce be [2] c2 b4 [2] d5 bf [2] ce f1 [2] f3 }

  condition:
    any of them
}