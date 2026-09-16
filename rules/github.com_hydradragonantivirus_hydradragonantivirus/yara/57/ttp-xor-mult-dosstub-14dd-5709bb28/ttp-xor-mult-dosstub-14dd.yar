rule TTP_XOR_MULT_DOSStub_14dd {
  strings:
    $key_14dd = { 40 b5 [2] 34 ad [2] 73 af [2] 34 be [2] 7a b2 [2] 76 b8 [2] 61 b3 [2] 7a fd [2] 47 }

  condition:
    any of them
}