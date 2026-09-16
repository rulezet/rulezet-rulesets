rule TTP_XOR_MULT_DOSStub_66d7 {
  strings:
    $key_66d7 = { 32 bf [2] 46 a7 [2] 01 a5 [2] 46 b4 [2] 08 b8 [2] 04 b2 [2] 13 b9 [2] 08 f7 [2] 35 }

  condition:
    any of them
}