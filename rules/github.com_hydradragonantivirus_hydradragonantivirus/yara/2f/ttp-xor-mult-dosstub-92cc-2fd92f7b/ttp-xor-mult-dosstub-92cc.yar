rule TTP_XOR_MULT_DOSStub_92cc {
  strings:
    $key_92cc = { c6 a4 [2] b2 bc [2] f5 be [2] b2 af [2] fc a3 [2] f0 a9 [2] e7 a2 [2] fc ec [2] c1 }

  condition:
    any of them
}