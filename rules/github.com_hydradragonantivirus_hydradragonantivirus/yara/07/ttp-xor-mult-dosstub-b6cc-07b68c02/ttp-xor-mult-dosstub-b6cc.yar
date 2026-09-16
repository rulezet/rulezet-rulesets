rule TTP_XOR_MULT_DOSStub_b6cc {
  strings:
    $key_b6cc = { e2 a4 [2] 96 bc [2] d1 be [2] 96 af [2] d8 a3 [2] d4 a9 [2] c3 a2 [2] d8 ec [2] e5 }

  condition:
    any of them
}