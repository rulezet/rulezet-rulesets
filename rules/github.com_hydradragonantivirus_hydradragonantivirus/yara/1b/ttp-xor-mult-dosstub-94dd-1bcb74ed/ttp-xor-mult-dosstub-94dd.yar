rule TTP_XOR_MULT_DOSStub_94dd {
  strings:
    $key_94dd = { c0 b5 [2] b4 ad [2] f3 af [2] b4 be [2] fa b2 [2] f6 b8 [2] e1 b3 [2] fa fd [2] c7 }

  condition:
    any of them
}