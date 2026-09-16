rule TTP_XOR_MULT_DOSStub_b1dd {
  strings:
    $key_b1dd = { e5 b5 [2] 91 ad [2] d6 af [2] 91 be [2] df b2 [2] d3 b8 [2] c4 b3 [2] df fd [2] e2 }

  condition:
    any of them
}