rule TTP_XOR_MULT_DOSStub_83dd {
  strings:
    $key_83dd = { d7 b5 [2] a3 ad [2] e4 af [2] a3 be [2] ed b2 [2] e1 b8 [2] f6 b3 [2] ed fd [2] d0 }

  condition:
    any of them
}