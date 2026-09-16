rule TTP_XOR_MULT_DOSStub_45d1 {
  strings:
    $key_45d1 = { 11 b9 [2] 65 a1 [2] 22 a3 [2] 65 b2 [2] 2b be [2] 27 b4 [2] 30 bf [2] 2b f1 [2] 16 }

  condition:
    any of them
}