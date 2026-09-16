rule TTP_XOR_MULT_DOSStub_30dd {
  strings:
    $key_30dd = { 64 b5 [2] 10 ad [2] 57 af [2] 10 be [2] 5e b2 [2] 52 b8 [2] 45 b3 [2] 5e fd [2] 63 }

  condition:
    any of them
}