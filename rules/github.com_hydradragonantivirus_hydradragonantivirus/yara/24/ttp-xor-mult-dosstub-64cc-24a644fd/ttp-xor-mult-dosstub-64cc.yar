rule TTP_XOR_MULT_DOSStub_64cc {
  strings:
    $key_64cc = { 30 a4 [2] 44 bc [2] 03 be [2] 44 af [2] 0a a3 [2] 06 a9 [2] 11 a2 [2] 0a ec [2] 37 }

  condition:
    any of them
}