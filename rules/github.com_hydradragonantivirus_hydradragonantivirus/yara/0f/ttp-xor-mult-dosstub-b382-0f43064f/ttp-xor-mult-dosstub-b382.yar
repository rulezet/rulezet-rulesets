rule TTP_XOR_MULT_DOSStub_b382 {
  strings:
    $key_b382 = { e7 ea [2] 93 f2 [2] d4 f0 [2] 93 e1 [2] dd ed [2] d1 e7 [2] c6 ec [2] dd a2 [2] e0 }

  condition:
    any of them
}