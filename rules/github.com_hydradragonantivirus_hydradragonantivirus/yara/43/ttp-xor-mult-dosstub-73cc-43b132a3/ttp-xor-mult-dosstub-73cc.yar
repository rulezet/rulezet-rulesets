rule TTP_XOR_MULT_DOSStub_73cc {
  strings:
    $key_73cc = { 27 a4 [2] 53 bc [2] 14 be [2] 53 af [2] 1d a3 [2] 11 a9 [2] 06 a2 [2] 1d ec [2] 20 }

  condition:
    any of them
}