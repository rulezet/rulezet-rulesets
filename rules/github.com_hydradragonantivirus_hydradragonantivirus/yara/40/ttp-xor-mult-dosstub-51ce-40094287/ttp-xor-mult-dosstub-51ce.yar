rule TTP_XOR_MULT_DOSStub_51ce {
  strings:
    $key_51ce = { 05 a6 [2] 71 be [2] 36 bc [2] 71 ad [2] 3f a1 [2] 33 ab [2] 24 a0 [2] 3f ee [2] 02 }

  condition:
    any of them
}