rule TTP_XOR_MULT_DOSStub_72d6 {
  strings:
    $key_72d6 = { 26 be [2] 52 a6 [2] 15 a4 [2] 52 b5 [2] 1c b9 [2] 10 b3 [2] 07 b8 [2] 1c f6 [2] 21 }

  condition:
    any of them
}