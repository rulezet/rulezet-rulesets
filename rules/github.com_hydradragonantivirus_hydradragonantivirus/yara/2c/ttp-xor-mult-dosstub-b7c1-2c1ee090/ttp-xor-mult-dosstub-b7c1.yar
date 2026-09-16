rule TTP_XOR_MULT_DOSStub_b7c1 {
  strings:
    $key_b7c1 = { e3 a9 [2] 97 b1 [2] d0 b3 [2] 97 a2 [2] d9 ae [2] d5 a4 [2] c2 af [2] d9 e1 [2] e4 }

  condition:
    any of them
}