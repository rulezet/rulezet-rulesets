rule TTP_XOR_MULT_DOSStub_05dd {
  strings:
    $key_05dd = { 51 b5 [2] 25 ad [2] 62 af [2] 25 be [2] 6b b2 [2] 67 b8 [2] 70 b3 [2] 6b fd [2] 56 }

  condition:
    any of them
}