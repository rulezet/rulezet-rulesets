rule TTP_XOR_MULT_DOSStub_72d1 {
  strings:
    $key_72d1 = { 26 b9 [2] 52 a1 [2] 15 a3 [2] 52 b2 [2] 1c be [2] 10 b4 [2] 07 bf [2] 1c f1 [2] 21 }

  condition:
    any of them
}