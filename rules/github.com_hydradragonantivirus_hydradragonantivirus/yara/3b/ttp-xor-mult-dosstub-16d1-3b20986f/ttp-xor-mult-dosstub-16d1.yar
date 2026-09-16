rule TTP_XOR_MULT_DOSStub_16d1 {
  strings:
    $key_16d1 = { 42 b9 [2] 36 a1 [2] 71 a3 [2] 36 b2 [2] 78 be [2] 74 b4 [2] 63 bf [2] 78 f1 [2] 45 }

  condition:
    any of them
}