rule TTP_XOR_MULT_DOSStub_35dd {
  strings:
    $key_35dd = { 61 b5 [2] 15 ad [2] 52 af [2] 15 be [2] 5b b2 [2] 57 b8 [2] 40 b3 [2] 5b fd [2] 66 }

  condition:
    any of them
}