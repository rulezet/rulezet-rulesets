rule TTP_XOR_MULT_DOSStub_18dd {
  strings:
    $key_18dd = { 4c b5 [2] 38 ad [2] 7f af [2] 38 be [2] 76 b2 [2] 7a b8 [2] 6d b3 [2] 76 fd [2] 4b }

  condition:
    any of them
}