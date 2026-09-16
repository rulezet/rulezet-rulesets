rule TTP_XOR_MULT_DOSStub_41ce {
  strings:
    $key_41ce = { 15 a6 [2] 61 be [2] 26 bc [2] 61 ad [2] 2f a1 [2] 23 ab [2] 34 a0 [2] 2f ee [2] 12 }

  condition:
    any of them
}