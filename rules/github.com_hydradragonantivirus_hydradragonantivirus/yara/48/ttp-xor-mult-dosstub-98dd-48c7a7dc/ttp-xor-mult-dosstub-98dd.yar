rule TTP_XOR_MULT_DOSStub_98dd {
  strings:
    $key_98dd = { cc b5 [2] b8 ad [2] ff af [2] b8 be [2] f6 b2 [2] fa b8 [2] ed b3 [2] f6 fd [2] cb }

  condition:
    any of them
}