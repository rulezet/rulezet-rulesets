rule TTP_XOR_MULT_DOSStub_53dd {
  strings:
    $key_53dd = { 07 b5 [2] 73 ad [2] 34 af [2] 73 be [2] 3d b2 [2] 31 b8 [2] 26 b3 [2] 3d fd [2] 00 }

  condition:
    any of them
}