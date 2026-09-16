rule TTP_XOR_MULT_DOSStub_04d1 {
  strings:
    $key_04d1 = { 50 b9 [2] 24 a1 [2] 63 a3 [2] 24 b2 [2] 6a be [2] 66 b4 [2] 71 bf [2] 6a f1 [2] 57 }

  condition:
    any of them
}