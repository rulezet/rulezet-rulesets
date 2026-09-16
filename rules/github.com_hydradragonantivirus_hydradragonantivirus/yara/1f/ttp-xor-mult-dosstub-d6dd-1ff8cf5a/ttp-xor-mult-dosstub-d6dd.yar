rule TTP_XOR_MULT_DOSStub_d6dd {
  strings:
    $key_d6dd = { 82 b5 [2] f6 ad [2] b1 af [2] f6 be [2] b8 b2 [2] b4 b8 [2] a3 b3 [2] b8 fd [2] 85 }

  condition:
    any of them
}