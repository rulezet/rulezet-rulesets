rule TTP_XOR_MULT_DOSStub_e2d0 {
  strings:
    $key_e2d0 = { b6 b8 [2] c2 a0 [2] 85 a2 [2] c2 b3 [2] 8c bf [2] 80 b5 [2] 97 be [2] 8c f0 [2] b1 }

  condition:
    any of them
}