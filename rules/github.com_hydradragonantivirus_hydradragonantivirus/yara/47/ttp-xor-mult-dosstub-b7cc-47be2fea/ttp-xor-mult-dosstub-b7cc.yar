rule TTP_XOR_MULT_DOSStub_b7cc {
  strings:
    $key_b7cc = { e3 a4 [2] 97 bc [2] d0 be [2] 97 af [2] d9 a3 [2] d5 a9 [2] c2 a2 [2] d9 ec [2] e4 }

  condition:
    any of them
}