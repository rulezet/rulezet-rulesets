rule TTP_XOR_MULT_DOSStub_14cc {
  strings:
    $key_14cc = { 40 a4 [2] 34 bc [2] 73 be [2] 34 af [2] 7a a3 [2] 76 a9 [2] 61 a2 [2] 7a ec [2] 47 }

  condition:
    any of them
}