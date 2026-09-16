rule TTP_XOR_MULT_DOSStub_72d7 {
  strings:
    $key_72d7 = { 26 bf [2] 52 a7 [2] 15 a5 [2] 52 b4 [2] 1c b8 [2] 10 b2 [2] 07 b9 [2] 1c f7 [2] 21 }

  condition:
    any of them
}