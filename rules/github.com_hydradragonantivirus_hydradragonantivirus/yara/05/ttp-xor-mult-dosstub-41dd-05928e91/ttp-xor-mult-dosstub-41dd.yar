rule TTP_XOR_MULT_DOSStub_41dd {
  strings:
    $key_41dd = { 15 b5 [2] 61 ad [2] 26 af [2] 61 be [2] 2f b2 [2] 23 b8 [2] 34 b3 [2] 2f fd [2] 12 }

  condition:
    any of them
}