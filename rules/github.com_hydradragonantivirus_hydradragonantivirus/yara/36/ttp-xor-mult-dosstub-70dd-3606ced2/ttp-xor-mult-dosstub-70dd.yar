rule TTP_XOR_MULT_DOSStub_70dd {
  strings:
    $key_70dd = { 24 b5 [2] 50 ad [2] 17 af [2] 50 be [2] 1e b2 [2] 12 b8 [2] 05 b3 [2] 1e fd [2] 23 }

  condition:
    any of them
}