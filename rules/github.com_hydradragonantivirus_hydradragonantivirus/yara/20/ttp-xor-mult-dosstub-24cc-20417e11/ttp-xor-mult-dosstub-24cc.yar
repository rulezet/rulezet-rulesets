rule TTP_XOR_MULT_DOSStub_24cc {
  strings:
    $key_24cc = { 70 a4 [2] 04 bc [2] 43 be [2] 04 af [2] 4a a3 [2] 46 a9 [2] 51 a2 [2] 4a ec [2] 77 }

  condition:
    any of them
}