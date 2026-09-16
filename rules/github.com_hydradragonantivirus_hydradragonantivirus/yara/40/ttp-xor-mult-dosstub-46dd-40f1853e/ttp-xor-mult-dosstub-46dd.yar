rule TTP_XOR_MULT_DOSStub_46dd {
  strings:
    $key_46dd = { 12 b5 [2] 66 ad [2] 21 af [2] 66 be [2] 28 b2 [2] 24 b8 [2] 33 b3 [2] 28 fd [2] 15 }

  condition:
    any of them
}