rule TTP_XOR_MULT_DOSStub_96cc {
  strings:
    $key_96cc = { c2 a4 [2] b6 bc [2] f1 be [2] b6 af [2] f8 a3 [2] f4 a9 [2] e3 a2 [2] f8 ec [2] c5 }

  condition:
    any of them
}