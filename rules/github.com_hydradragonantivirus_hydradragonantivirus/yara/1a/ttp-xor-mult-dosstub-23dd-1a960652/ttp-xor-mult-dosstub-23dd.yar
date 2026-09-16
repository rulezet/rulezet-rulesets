rule TTP_XOR_MULT_DOSStub_23dd {
  strings:
    $key_23dd = { 77 b5 [2] 03 ad [2] 44 af [2] 03 be [2] 4d b2 [2] 41 b8 [2] 56 b3 [2] 4d fd [2] 70 }

  condition:
    any of them
}