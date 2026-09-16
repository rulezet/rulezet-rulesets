rule TTP_XOR_MULT_DOSStub_b3cc {
  strings:
    $key_b3cc = { e7 a4 [2] 93 bc [2] d4 be [2] 93 af [2] dd a3 [2] d1 a9 [2] c6 a2 [2] dd ec [2] e0 }

  condition:
    any of them
}