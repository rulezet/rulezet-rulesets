rule TTP_XOR_MULT_DOSStub_e2d1 {
  strings:
    $key_e2d1 = { b6 b9 [2] c2 a1 [2] 85 a3 [2] c2 b2 [2] 8c be [2] 80 b4 [2] 97 bf [2] 8c f1 [2] b1 }

  condition:
    any of them
}