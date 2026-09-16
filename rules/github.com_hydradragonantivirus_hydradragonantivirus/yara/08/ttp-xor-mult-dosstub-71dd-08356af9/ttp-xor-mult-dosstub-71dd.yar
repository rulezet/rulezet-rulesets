rule TTP_XOR_MULT_DOSStub_71dd {
  strings:
    $key_71dd = { 25 b5 [2] 51 ad [2] 16 af [2] 51 be [2] 1f b2 [2] 13 b8 [2] 04 b3 [2] 1f fd [2] 22 }

  condition:
    any of them
}