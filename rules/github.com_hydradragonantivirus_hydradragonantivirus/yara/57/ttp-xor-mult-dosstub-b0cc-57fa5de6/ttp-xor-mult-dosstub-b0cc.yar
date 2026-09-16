rule TTP_XOR_MULT_DOSStub_b0cc {
  strings:
    $key_b0cc = { e4 a4 [2] 90 bc [2] d7 be [2] 90 af [2] de a3 [2] d2 a9 [2] c5 a2 [2] de ec [2] e3 }

  condition:
    any of them
}