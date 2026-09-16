rule TTP_XOR_MULT_DOSStub_85cc {
  strings:
    $key_85cc = { d1 a4 [2] a5 bc [2] e2 be [2] a5 af [2] eb a3 [2] e7 a9 [2] f0 a2 [2] eb ec [2] d6 }

  condition:
    any of them
}