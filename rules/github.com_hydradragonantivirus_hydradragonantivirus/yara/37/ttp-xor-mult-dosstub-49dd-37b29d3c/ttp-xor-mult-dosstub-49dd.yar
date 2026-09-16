rule TTP_XOR_MULT_DOSStub_49dd {
  strings:
    $key_49dd = { 1d b5 [2] 69 ad [2] 2e af [2] 69 be [2] 27 b2 [2] 2b b8 [2] 3c b3 [2] 27 fd [2] 1a }

  condition:
    any of them
}