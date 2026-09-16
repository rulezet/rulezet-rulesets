rule TTP_XOR_MULT_DOSStub_b6c0 {
  strings:
    $key_b6c0 = { e2 a8 [2] 96 b0 [2] d1 b2 [2] 96 a3 [2] d8 af [2] d4 a5 [2] c3 ae [2] d8 e0 [2] e5 }

  condition:
    any of them
}