rule TTP_XOR_MULT_DOSStub_b5d7 {
  strings:
    $key_b5d7 = { e1 bf [2] 95 a7 [2] d2 a5 [2] 95 b4 [2] db b8 [2] d7 b2 [2] c0 b9 [2] db f7 [2] e6 }

  condition:
    any of them
}