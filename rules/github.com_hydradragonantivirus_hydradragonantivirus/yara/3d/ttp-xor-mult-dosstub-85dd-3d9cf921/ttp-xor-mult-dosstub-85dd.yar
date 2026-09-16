rule TTP_XOR_MULT_DOSStub_85dd {
  strings:
    $key_85dd = { d1 b5 [2] a5 ad [2] e2 af [2] a5 be [2] eb b2 [2] e7 b8 [2] f0 b3 [2] eb fd [2] d6 }

  condition:
    any of them
}