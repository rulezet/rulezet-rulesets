rule TTP_XOR_MULT_DOSStub_56dd {
  strings:
    $key_56dd = { 02 b5 [2] 76 ad [2] 31 af [2] 76 be [2] 38 b2 [2] 34 b8 [2] 23 b3 [2] 38 fd [2] 05 }

  condition:
    any of them
}