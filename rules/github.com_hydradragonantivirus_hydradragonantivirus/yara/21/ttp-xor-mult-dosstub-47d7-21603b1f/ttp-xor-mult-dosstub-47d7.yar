rule TTP_XOR_MULT_DOSStub_47d7 {
  strings:
    $key_47d7 = { 13 bf [2] 67 a7 [2] 20 a5 [2] 67 b4 [2] 29 b8 [2] 25 b2 [2] 32 b9 [2] 29 f7 [2] 14 }

  condition:
    any of them
}