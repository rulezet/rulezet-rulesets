rule TTP_XOR_MULT_DOSStub_d5cc {
  strings:
    $key_d5cc = { 81 a4 [2] f5 bc [2] b2 be [2] f5 af [2] bb a3 [2] b7 a9 [2] a0 a2 [2] bb ec [2] 86 }

  condition:
    any of them
}