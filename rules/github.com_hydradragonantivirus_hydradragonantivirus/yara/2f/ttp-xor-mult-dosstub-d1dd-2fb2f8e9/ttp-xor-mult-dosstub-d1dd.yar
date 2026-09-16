rule TTP_XOR_MULT_DOSStub_d1dd {
  strings:
    $key_d1dd = { 85 b5 [2] f1 ad [2] b6 af [2] f1 be [2] bf b2 [2] b3 b8 [2] a4 b3 [2] bf fd [2] 82 }

  condition:
    any of them
}