rule TTP_XOR_MULT_DOSStub_01dd {
  strings:
    $key_01dd = { 55 b5 [2] 21 ad [2] 66 af [2] 21 be [2] 6f b2 [2] 63 b8 [2] 74 b3 [2] 6f fd [2] 52 }

  condition:
    any of them
}