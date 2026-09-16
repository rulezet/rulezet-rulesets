rule TTP_XOR_MULT_DOSStub_13dd {
  strings:
    $key_13dd = { 47 b5 [2] 33 ad [2] 74 af [2] 33 be [2] 7d b2 [2] 71 b8 [2] 66 b3 [2] 7d fd [2] 40 }

  condition:
    any of them
}