rule TTP_XOR_MULT_DOSStub_a1dd {
  strings:
    $key_a1dd = { f5 b5 [2] 81 ad [2] c6 af [2] 81 be [2] cf b2 [2] c3 b8 [2] d4 b3 [2] cf fd [2] f2 }

  condition:
    any of them
}