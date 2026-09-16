rule TTP_XOR_MULT_DOSStub_10d7 {
  strings:
    $key_10d7 = { 44 bf [2] 30 a7 [2] 77 a5 [2] 30 b4 [2] 7e b8 [2] 72 b2 [2] 65 b9 [2] 7e f7 [2] 43 }

  condition:
    any of them
}