rule TTP_XOR_MULT_DOSStub_03cc {
  strings:
    $key_03cc = { 57 a4 [2] 23 bc [2] 64 be [2] 23 af [2] 6d a3 [2] 61 a9 [2] 76 a2 [2] 6d ec [2] 50 }

  condition:
    any of them
}