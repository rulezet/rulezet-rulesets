rule TTP_XOR_MULT_DOSStub_94cc {
  strings:
    $key_94cc = { c0 a4 [2] b4 bc [2] f3 be [2] b4 af [2] fa a3 [2] f6 a9 [2] e1 a2 [2] fa ec [2] c7 }

  condition:
    any of them
}