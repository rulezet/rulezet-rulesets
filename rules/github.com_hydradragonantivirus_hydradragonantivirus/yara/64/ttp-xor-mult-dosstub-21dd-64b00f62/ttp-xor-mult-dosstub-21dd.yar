rule TTP_XOR_MULT_DOSStub_21dd {
  strings:
    $key_21dd = { 75 b5 [2] 01 ad [2] 46 af [2] 01 be [2] 4f b2 [2] 43 b8 [2] 54 b3 [2] 4f fd [2] 72 }

  condition:
    any of them
}