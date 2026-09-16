rule TTP_XOR_MULT_DOSStub_62d6 {
  strings:
    $key_62d6 = { 36 be [2] 42 a6 [2] 05 a4 [2] 42 b5 [2] 0c b9 [2] 00 b3 [2] 17 b8 [2] 0c f6 [2] 31 }

  condition:
    any of them
}