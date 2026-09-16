rule TTP_XOR_MULT_DOSStub_11dd {
  strings:
    $key_11dd = { 45 b5 [2] 31 ad [2] 76 af [2] 31 be [2] 7f b2 [2] 73 b8 [2] 64 b3 [2] 7f fd [2] 42 }

  condition:
    any of them
}