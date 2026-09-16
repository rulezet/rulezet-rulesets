rule TTP_XOR_MULT_DOSStub_b7d4 {
  strings:
    $key_b7d4 = { e3 bc [2] 97 a4 [2] d0 a6 [2] 97 b7 [2] d9 bb [2] d5 b1 [2] c2 ba [2] d9 f4 [2] e4 }

  condition:
    any of them
}