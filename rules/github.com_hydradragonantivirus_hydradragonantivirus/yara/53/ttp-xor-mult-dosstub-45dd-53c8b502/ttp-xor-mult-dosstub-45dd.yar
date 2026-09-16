rule TTP_XOR_MULT_DOSStub_45dd {
  strings:
    $key_45dd = { 11 b5 [2] 65 ad [2] 22 af [2] 65 be [2] 2b b2 [2] 27 b8 [2] 30 b3 [2] 2b fd [2] 16 }

  condition:
    any of them
}