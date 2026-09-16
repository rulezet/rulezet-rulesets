rule TTP_XOR_MULT_DOSStub_33dd {
  strings:
    $key_33dd = { 67 b5 [2] 13 ad [2] 54 af [2] 13 be [2] 5d b2 [2] 51 b8 [2] 46 b3 [2] 5d fd [2] 60 }

  condition:
    any of them
}