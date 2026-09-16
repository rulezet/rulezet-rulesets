rule TTP_XOR_MULT_DOSStub_44cc {
  strings:
    $key_44cc = { 10 a4 [2] 64 bc [2] 23 be [2] 64 af [2] 2a a3 [2] 26 a9 [2] 31 a2 [2] 2a ec [2] 17 }

  condition:
    any of them
}