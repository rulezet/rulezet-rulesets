rule TTP_XOR_MULT_DOSStub_19dd {
  strings:
    $key_19dd = { 4d b5 [2] 39 ad [2] 7e af [2] 39 be [2] 77 b2 [2] 7b b8 [2] 6c b3 [2] 77 fd [2] 4a }

  condition:
    any of them
}