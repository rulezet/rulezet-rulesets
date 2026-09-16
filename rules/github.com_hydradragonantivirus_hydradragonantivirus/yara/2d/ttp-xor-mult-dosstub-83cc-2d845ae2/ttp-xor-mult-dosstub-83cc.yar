rule TTP_XOR_MULT_DOSStub_83cc {
  strings:
    $key_83cc = { d7 a4 [2] a3 bc [2] e4 be [2] a3 af [2] ed a3 [2] e1 a9 [2] f6 a2 [2] ed ec [2] d0 }

  condition:
    any of them
}