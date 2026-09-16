rule TTP_XOR_MULT_DOSStub_28dd {
  strings:
    $key_28dd = { 7c b5 [2] 08 ad [2] 4f af [2] 08 be [2] 46 b2 [2] 4a b8 [2] 5d b3 [2] 46 fd [2] 7b }

  condition:
    any of them
}