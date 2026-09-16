rule TTP_XOR_MULT_DOSStub_12d6 {
  strings:
    $key_12d6 = { 46 be [2] 32 a6 [2] 75 a4 [2] 32 b5 [2] 7c b9 [2] 70 b3 [2] 67 b8 [2] 7c f6 [2] 41 }

  condition:
    any of them
}