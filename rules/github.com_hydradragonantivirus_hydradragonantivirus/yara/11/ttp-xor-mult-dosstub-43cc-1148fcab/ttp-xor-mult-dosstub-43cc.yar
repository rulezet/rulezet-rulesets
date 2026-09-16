rule TTP_XOR_MULT_DOSStub_43cc {
  strings:
    $key_43cc = { 17 a4 [2] 63 bc [2] 24 be [2] 63 af [2] 2d a3 [2] 21 a9 [2] 36 a2 [2] 2d ec [2] 10 }

  condition:
    any of them
}