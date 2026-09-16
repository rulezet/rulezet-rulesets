rule TTP_XOR_MULT_DOSStub_75dd {
  strings:
    $key_75dd = { 21 b5 [2] 55 ad [2] 12 af [2] 55 be [2] 1b b2 [2] 17 b8 [2] 00 b3 [2] 1b fd [2] 26 }

  condition:
    any of them
}