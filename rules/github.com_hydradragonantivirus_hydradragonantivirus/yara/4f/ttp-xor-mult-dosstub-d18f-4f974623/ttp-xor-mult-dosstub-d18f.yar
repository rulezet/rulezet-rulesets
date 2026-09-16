rule TTP_XOR_MULT_DOSStub_d18f {
  strings:
    $key_d18f = { 85 e7 [2] f1 ff [2] b6 fd [2] f1 ec [2] bf e0 [2] b3 ea [2] a4 e1 [2] bf af [2] 82 }

  condition:
    any of them
}