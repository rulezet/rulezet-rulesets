rule TTP_XOR_MULT_DOSStub_02d6 {
  strings:
    $key_02d6 = { 56 be [2] 22 a6 [2] 65 a4 [2] 22 b5 [2] 6c b9 [2] 60 b3 [2] 77 b8 [2] 6c f6 [2] 51 }

  condition:
    any of them
}