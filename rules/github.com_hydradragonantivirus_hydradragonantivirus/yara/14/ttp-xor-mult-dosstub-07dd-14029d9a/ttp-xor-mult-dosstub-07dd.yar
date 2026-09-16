rule TTP_XOR_MULT_DOSStub_07dd {
  strings:
    $key_07dd = { 53 b5 [2] 27 ad [2] 60 af [2] 27 be [2] 69 b2 [2] 65 b8 [2] 72 b3 [2] 69 fd [2] 54 }

  condition:
    any of them
}