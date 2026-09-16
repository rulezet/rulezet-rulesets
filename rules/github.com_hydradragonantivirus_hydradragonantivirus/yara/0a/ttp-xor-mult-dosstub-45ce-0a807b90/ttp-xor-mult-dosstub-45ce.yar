rule TTP_XOR_MULT_DOSStub_45ce {
  strings:
    $key_45ce = { 11 a6 [2] 65 be [2] 22 bc [2] 65 ad [2] 2b a1 [2] 27 ab [2] 30 a0 [2] 2b ee [2] 16 }

  condition:
    any of them
}