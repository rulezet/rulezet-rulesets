rule TTP_XOR_MULT_DOSStub_22d6 {
  strings:
    $key_22d6 = { 76 be [2] 02 a6 [2] 45 a4 [2] 02 b5 [2] 4c b9 [2] 40 b3 [2] 57 b8 [2] 4c f6 [2] 71 }

  condition:
    any of them
}