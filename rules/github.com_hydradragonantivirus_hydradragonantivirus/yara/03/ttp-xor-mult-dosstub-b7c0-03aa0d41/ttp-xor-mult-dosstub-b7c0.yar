rule TTP_XOR_MULT_DOSStub_b7c0 {
  strings:
    $key_b7c0 = { e3 a8 [2] 97 b0 [2] d0 b2 [2] 97 a3 [2] d9 af [2] d5 a5 [2] c2 ae [2] d9 e0 [2] e4 }

  condition:
    any of them
}