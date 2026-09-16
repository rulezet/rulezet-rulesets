rule TTP_XOR_MULT_DOSStub_95dd {
  strings:
    $key_95dd = { c1 b5 [2] b5 ad [2] f2 af [2] b5 be [2] fb b2 [2] f7 b8 [2] e0 b3 [2] fb fd [2] c6 }

  condition:
    any of them
}