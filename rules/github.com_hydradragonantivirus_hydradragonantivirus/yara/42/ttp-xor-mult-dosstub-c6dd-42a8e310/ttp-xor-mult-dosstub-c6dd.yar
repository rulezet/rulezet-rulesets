rule TTP_XOR_MULT_DOSStub_c6dd {
  strings:
    $key_c6dd = { 92 b5 [2] e6 ad [2] a1 af [2] e6 be [2] a8 b2 [2] a4 b8 [2] b3 b3 [2] a8 fd [2] 95 }

  condition:
    any of them
}