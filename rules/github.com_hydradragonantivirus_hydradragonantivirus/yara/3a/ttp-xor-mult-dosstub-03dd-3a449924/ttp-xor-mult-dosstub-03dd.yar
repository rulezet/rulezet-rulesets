rule TTP_XOR_MULT_DOSStub_03dd {
  strings:
    $key_03dd = { 57 b5 [2] 23 ad [2] 64 af [2] 23 be [2] 6d b2 [2] 61 b8 [2] 76 b3 [2] 6d fd [2] 50 }

  condition:
    any of them
}