rule TTP_XOR_MULT_DOSStub_67dd {
  strings:
    $key_67dd = { 33 b5 [2] 47 ad [2] 00 af [2] 47 be [2] 09 b2 [2] 05 b8 [2] 12 b3 [2] 09 fd [2] 34 }

  condition:
    any of them
}