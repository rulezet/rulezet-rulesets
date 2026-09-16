rule TTP_XOR_MULT_DOSStub_37d1 {
  strings:
    $key_37d1 = { 63 b9 [2] 17 a1 [2] 50 a3 [2] 17 b2 [2] 59 be [2] 55 b4 [2] 42 bf [2] 59 f1 [2] 64 }

  condition:
    any of them
}