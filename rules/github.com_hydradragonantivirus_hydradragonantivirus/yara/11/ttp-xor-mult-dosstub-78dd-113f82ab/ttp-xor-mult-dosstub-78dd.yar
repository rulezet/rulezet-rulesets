rule TTP_XOR_MULT_DOSStub_78dd {
  strings:
    $key_78dd = { 2c b5 [2] 58 ad [2] 1f af [2] 58 be [2] 16 b2 [2] 1a b8 [2] 0d b3 [2] 16 fd [2] 2b }

  condition:
    any of them
}