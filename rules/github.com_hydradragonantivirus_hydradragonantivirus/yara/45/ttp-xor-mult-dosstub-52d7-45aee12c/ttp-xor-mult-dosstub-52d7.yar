rule TTP_XOR_MULT_DOSStub_52d7 {
  strings:
    $key_52d7 = { 06 bf [2] 72 a7 [2] 35 a5 [2] 72 b4 [2] 3c b8 [2] 30 b2 [2] 27 b9 [2] 3c f7 [2] 01 }

  condition:
    any of them
}