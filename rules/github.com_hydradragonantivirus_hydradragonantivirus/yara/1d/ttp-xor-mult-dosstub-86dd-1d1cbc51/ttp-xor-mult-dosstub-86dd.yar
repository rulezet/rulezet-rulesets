rule TTP_XOR_MULT_DOSStub_86dd {
  strings:
    $key_86dd = { d2 b5 [2] a6 ad [2] e1 af [2] a6 be [2] e8 b2 [2] e4 b8 [2] f3 b3 [2] e8 fd [2] d5 }

  condition:
    any of them
}