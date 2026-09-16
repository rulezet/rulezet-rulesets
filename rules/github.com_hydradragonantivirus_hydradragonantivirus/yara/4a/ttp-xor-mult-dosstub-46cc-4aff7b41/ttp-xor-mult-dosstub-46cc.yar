rule TTP_XOR_MULT_DOSStub_46cc {
  strings:
    $key_46cc = { 12 a4 [2] 66 bc [2] 21 be [2] 66 af [2] 28 a3 [2] 24 a9 [2] 33 a2 [2] 28 ec [2] 15 }

  condition:
    any of them
}