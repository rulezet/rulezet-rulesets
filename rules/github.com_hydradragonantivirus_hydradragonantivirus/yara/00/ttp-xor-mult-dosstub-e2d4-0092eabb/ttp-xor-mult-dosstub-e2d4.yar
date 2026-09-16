rule TTP_XOR_MULT_DOSStub_e2d4 {
  strings:
    $key_e2d4 = { b6 bc [2] c2 a4 [2] 85 a6 [2] c2 b7 [2] 8c bb [2] 80 b1 [2] 97 ba [2] 8c f4 [2] b1 }

  condition:
    any of them
}