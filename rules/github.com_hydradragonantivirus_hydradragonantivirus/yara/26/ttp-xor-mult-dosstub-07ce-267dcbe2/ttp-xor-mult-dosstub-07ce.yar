rule TTP_XOR_MULT_DOSStub_07ce {
  strings:
    $key_07ce = { 53 a6 [2] 27 be [2] 60 bc [2] 27 ad [2] 69 a1 [2] 65 ab [2] 72 a0 [2] 69 ee [2] 54 }

  condition:
    any of them
}