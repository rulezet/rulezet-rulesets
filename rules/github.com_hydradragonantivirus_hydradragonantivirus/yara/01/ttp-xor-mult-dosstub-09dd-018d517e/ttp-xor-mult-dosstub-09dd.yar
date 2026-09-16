rule TTP_XOR_MULT_DOSStub_09dd {
  strings:
    $key_09dd = { 5d b5 [2] 29 ad [2] 6e af [2] 29 be [2] 67 b2 [2] 6b b8 [2] 7c b3 [2] 67 fd [2] 5a }

  condition:
    any of them
}