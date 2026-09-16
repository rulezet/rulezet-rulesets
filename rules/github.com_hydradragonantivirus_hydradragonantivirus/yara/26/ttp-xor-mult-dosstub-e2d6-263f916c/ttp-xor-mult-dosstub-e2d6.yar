rule TTP_XOR_MULT_DOSStub_e2d6 {
  strings:
    $key_e2d6 = { b6 be [2] c2 a6 [2] 85 a4 [2] c2 b5 [2] 8c b9 [2] 80 b3 [2] 97 b8 [2] 8c f6 [2] b1 }

  condition:
    any of them
}