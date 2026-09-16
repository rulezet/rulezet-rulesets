rule TTP_XOR_MULT_DOSStub_03ce {
  strings:
    $key_03ce = { 57 a6 [2] 23 be [2] 64 bc [2] 23 ad [2] 6d a1 [2] 61 ab [2] 76 a0 [2] 6d ee [2] 50 }

  condition:
    any of them
}