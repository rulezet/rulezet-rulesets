rule TTP_XOR_MULT_DOSStub_b7d2 {
  strings:
    $key_b7d2 = { e3 ba [2] 97 a2 [2] d0 a0 [2] 97 b1 [2] d9 bd [2] d5 b7 [2] c2 bc [2] d9 f2 [2] e4 }

  condition:
    any of them
}