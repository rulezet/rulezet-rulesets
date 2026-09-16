rule TTP_XOR_MULT_DOSStub_91dd {
  strings:
    $key_91dd = { c5 b5 [2] b1 ad [2] f6 af [2] b1 be [2] ff b2 [2] f3 b8 [2] e4 b3 [2] ff fd [2] c2 }

  condition:
    any of them
}