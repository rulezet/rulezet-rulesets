rule TTP_XOR_MULT_DOSStub_90cc {
  strings:
    $key_90cc = { c4 a4 [2] b0 bc [2] f7 be [2] b0 af [2] fe a3 [2] f2 a9 [2] e5 a2 [2] fe ec [2] c3 }

  condition:
    any of them
}