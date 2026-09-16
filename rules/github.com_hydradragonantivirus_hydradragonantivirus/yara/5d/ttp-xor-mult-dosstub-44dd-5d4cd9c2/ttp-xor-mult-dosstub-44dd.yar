rule TTP_XOR_MULT_DOSStub_44dd {
  strings:
    $key_44dd = { 10 b5 [2] 64 ad [2] 23 af [2] 64 be [2] 2a b2 [2] 26 b8 [2] 31 b3 [2] 2a fd [2] 17 }

  condition:
    any of them
}