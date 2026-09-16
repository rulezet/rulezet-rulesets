rule TTP_XOR_MULT_DOSStub_f1dd {
  strings:
    $key_f1dd = { a5 b5 [2] d1 ad [2] 96 af [2] d1 be [2] 9f b2 [2] 93 b8 [2] 84 b3 [2] 9f fd [2] a2 }

  condition:
    any of them
}