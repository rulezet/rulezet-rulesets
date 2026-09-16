rule TTP_XOR_MULT_DOSStub_b5dd {
  strings:
    $key_b5dd = { e1 b5 [2] 95 ad [2] d2 af [2] 95 be [2] db b2 [2] d7 b8 [2] c0 b3 [2] db fd [2] e6 }

  condition:
    any of them
}