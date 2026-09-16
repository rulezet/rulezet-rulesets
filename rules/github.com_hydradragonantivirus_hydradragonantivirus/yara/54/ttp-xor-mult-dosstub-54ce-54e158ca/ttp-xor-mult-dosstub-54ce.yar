rule TTP_XOR_MULT_DOSStub_54ce {
  strings:
    $key_54ce = { 00 a6 [2] 74 be [2] 33 bc [2] 74 ad [2] 3a a1 [2] 36 ab [2] 21 a0 [2] 3a ee [2] 07 }

  condition:
    any of them
}