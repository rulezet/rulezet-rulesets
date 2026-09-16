rule TTP_XOR_MULT_DOSStub_74ce {
  strings:
    $key_74ce = { 20 a6 [2] 54 be [2] 13 bc [2] 54 ad [2] 1a a1 [2] 16 ab [2] 01 a0 [2] 1a ee [2] 27 }

  condition:
    any of them
}