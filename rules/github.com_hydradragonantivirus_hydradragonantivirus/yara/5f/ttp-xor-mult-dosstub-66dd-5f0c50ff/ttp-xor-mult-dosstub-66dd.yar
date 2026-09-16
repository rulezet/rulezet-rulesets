rule TTP_XOR_MULT_DOSStub_66dd {
  strings:
    $key_66dd = { 32 b5 [2] 46 ad [2] 01 af [2] 46 be [2] 08 b2 [2] 04 b8 [2] 13 b3 [2] 08 fd [2] 35 }

  condition:
    any of them
}