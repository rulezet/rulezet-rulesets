rule TTP_XOR_MULT_DOSStub_51dd {
  strings:
    $key_51dd = { 05 b5 [2] 71 ad [2] 36 af [2] 71 be [2] 3f b2 [2] 33 b8 [2] 24 b3 [2] 3f fd [2] 02 }

  condition:
    any of them
}