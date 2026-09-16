rule TTP_XOR_MULT_DOSStub_34cc {
  strings:
    $key_34cc = { 60 a4 [2] 14 bc [2] 53 be [2] 14 af [2] 5a a3 [2] 56 a9 [2] 41 a2 [2] 5a ec [2] 67 }

  condition:
    any of them
}