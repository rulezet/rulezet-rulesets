rule TTP_XOR_MULT_DOSStub_04ce {
  strings:
    $key_04ce = { 50 a6 [2] 24 be [2] 63 bc [2] 24 ad [2] 6a a1 [2] 66 ab [2] 71 a0 [2] 6a ee [2] 57 }

  condition:
    any of them
}