rule TTP_XOR_MULT_DOSStub_58dd {
  strings:
    $key_58dd = { 0c b5 [2] 78 ad [2] 3f af [2] 78 be [2] 36 b2 [2] 3a b8 [2] 2d b3 [2] 36 fd [2] 0b }

  condition:
    any of them
}