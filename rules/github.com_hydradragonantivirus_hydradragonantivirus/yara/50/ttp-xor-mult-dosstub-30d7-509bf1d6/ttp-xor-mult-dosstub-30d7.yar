rule TTP_XOR_MULT_DOSStub_30d7 {
  strings:
    $key_30d7 = { 64 bf [2] 10 a7 [2] 57 a5 [2] 10 b4 [2] 5e b8 [2] 52 b2 [2] 45 b9 [2] 5e f7 [2] 63 }

  condition:
    any of them
}