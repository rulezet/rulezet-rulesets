rule TTP_XOR_MULT_DOSStub_92dd {
  strings:
    $key_92dd = { c6 b5 [2] b2 ad [2] f5 af [2] b2 be [2] fc b2 [2] f0 b8 [2] e7 b3 [2] fc fd [2] c1 }

  condition:
    any of them
}