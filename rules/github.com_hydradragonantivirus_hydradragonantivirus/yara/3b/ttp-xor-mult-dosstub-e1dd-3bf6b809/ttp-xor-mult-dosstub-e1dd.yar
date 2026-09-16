rule TTP_XOR_MULT_DOSStub_e1dd {
  strings:
    $key_e1dd = { b5 b5 [2] c1 ad [2] 86 af [2] c1 be [2] 8f b2 [2] 83 b8 [2] 94 b3 [2] 8f fd [2] b2 }

  condition:
    any of them
}