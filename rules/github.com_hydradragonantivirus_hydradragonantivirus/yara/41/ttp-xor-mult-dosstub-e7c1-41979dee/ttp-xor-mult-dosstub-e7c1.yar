rule TTP_XOR_MULT_DOSStub_e7c1 {
  strings:
    $key_e7c1 = { b3 a9 [2] c7 b1 [2] 80 b3 [2] c7 a2 [2] 89 ae [2] 85 a4 [2] 92 af [2] 89 e1 [2] b4 }

  condition:
    any of them
}