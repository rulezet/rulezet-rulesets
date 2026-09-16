rule TTP_XOR_MULT_DOSStub_27d1 {
  strings:
    $key_27d1 = { 73 b9 [2] 07 a1 [2] 40 a3 [2] 07 b2 [2] 49 be [2] 45 b4 [2] 52 bf [2] 49 f1 [2] 74 }

  condition:
    any of them
}