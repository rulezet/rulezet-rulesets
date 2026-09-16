rule TTP_XOR_MULT_DOSStub_00d1 {
  strings:
    $key_00d1 = { 54 b9 [2] 20 a1 [2] 67 a3 [2] 20 b2 [2] 6e be [2] 62 b4 [2] 75 bf [2] 6e f1 [2] 53 }

  condition:
    any of them
}