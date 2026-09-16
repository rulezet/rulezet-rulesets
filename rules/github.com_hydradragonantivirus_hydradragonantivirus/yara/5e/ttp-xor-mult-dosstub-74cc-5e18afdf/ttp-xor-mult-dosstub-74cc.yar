rule TTP_XOR_MULT_DOSStub_74cc {
  strings:
    $key_74cc = { 20 a4 [2] 54 bc [2] 13 be [2] 54 af [2] 1a a3 [2] 16 a9 [2] 01 a2 [2] 1a ec [2] 27 }

  condition:
    any of them
}