rule TTP_XOR_MULT_DOSStub_e2c7 {
  strings:
    $key_e2c7 = { b6 af [2] c2 b7 [2] 85 b5 [2] c2 a4 [2] 8c a8 [2] 80 a2 [2] 97 a9 [2] 8c e7 [2] b1 }

  condition:
    any of them
}