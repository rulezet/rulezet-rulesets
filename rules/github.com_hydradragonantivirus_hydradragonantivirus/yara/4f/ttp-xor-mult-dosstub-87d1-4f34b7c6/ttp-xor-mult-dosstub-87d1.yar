rule TTP_XOR_MULT_DOSStub_87d1 {
  strings:
    $key_87d1 = { d3 b9 [2] a7 a1 [2] e0 a3 [2] a7 b2 [2] e9 be [2] e5 b4 [2] f2 bf [2] e9 f1 [2] d4 }

  condition:
    any of them
}