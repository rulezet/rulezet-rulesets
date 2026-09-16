rule TTP_XOR_MULT_DOSStub_a6dd {
  strings:
    $key_a6dd = { f2 b5 [2] 86 ad [2] c1 af [2] 86 be [2] c8 b2 [2] c4 b8 [2] d3 b3 [2] c8 fd [2] f5 }

  condition:
    any of them
}