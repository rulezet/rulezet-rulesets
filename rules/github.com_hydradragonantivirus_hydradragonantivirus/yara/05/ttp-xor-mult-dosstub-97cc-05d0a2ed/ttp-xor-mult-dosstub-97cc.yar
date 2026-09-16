rule TTP_XOR_MULT_DOSStub_97cc {
  strings:
    $key_97cc = { c3 a4 [2] b7 bc [2] f0 be [2] b7 af [2] f9 a3 [2] f5 a9 [2] e2 a2 [2] f9 ec [2] c4 }

  condition:
    any of them
}