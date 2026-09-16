rule TTP_XOR_MULT_DOSStub_63dd {
  strings:
    $key_63dd = { 37 b5 [2] 43 ad [2] 04 af [2] 43 be [2] 0d b2 [2] 01 b8 [2] 16 b3 [2] 0d fd [2] 30 }

  condition:
    any of them
}