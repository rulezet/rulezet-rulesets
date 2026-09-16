rule TTP_XOR_MULT_DOSStub_54cc {
  strings:
    $key_54cc = { 00 a4 [2] 74 bc [2] 33 be [2] 74 af [2] 3a a3 [2] 36 a9 [2] 21 a2 [2] 3a ec [2] 07 }

  condition:
    any of them
}