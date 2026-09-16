rule TTP_XOR_MULT_DOSStub_08dd {
  strings:
    $key_08dd = { 5c b5 [2] 28 ad [2] 6f af [2] 28 be [2] 66 b2 [2] 6a b8 [2] 7d b3 [2] 66 fd [2] 5b }

  condition:
    any of them
}