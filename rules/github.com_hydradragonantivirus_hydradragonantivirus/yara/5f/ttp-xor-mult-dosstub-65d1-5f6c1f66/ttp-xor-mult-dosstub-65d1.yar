rule TTP_XOR_MULT_DOSStub_65d1 {
  strings:
    $key_65d1 = { 31 b9 [2] 45 a1 [2] 02 a3 [2] 45 b2 [2] 0b be [2] 07 b4 [2] 10 bf [2] 0b f1 [2] 36 }

  condition:
    any of them
}