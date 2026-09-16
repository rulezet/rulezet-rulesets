rule TTP_XOR_MULT_DOSStub_14d7 {
  strings:
    $key_14d7 = { 40 bf [2] 34 a7 [2] 73 a5 [2] 34 b4 [2] 7a b8 [2] 76 b2 [2] 61 b9 [2] 7a f7 [2] 47 }

  condition:
    any of them
}