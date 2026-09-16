rule TTP_XOR_MULT_DOSStub_9b8f {
  strings:
    $key_9b8f = { cf e7 [2] bb ff [2] fc fd [2] bb ec [2] f5 e0 [2] f9 ea [2] ee e1 [2] f5 af [2] c8 }

  condition:
    any of them
}