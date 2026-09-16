rule TTP_XOR_MULT_DOSStub_20dd {
  strings:
    $key_20dd = { 74 b5 [2] 00 ad [2] 47 af [2] 00 be [2] 4e b2 [2] 42 b8 [2] 55 b3 [2] 4e fd [2] 73 }

  condition:
    any of them
}