rule TTP_XOR_MULT_DOSStub_14ce {
  strings:
    $key_14ce = { 40 a6 [2] 34 be [2] 73 bc [2] 34 ad [2] 7a a1 [2] 76 ab [2] 61 a0 [2] 7a ee [2] 47 }

  condition:
    any of them
}