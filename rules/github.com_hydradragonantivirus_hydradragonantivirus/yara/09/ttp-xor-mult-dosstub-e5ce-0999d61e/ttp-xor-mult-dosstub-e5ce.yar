rule TTP_XOR_MULT_DOSStub_e5ce {
  strings:
    $key_e5ce = { b1 a6 [2] c5 be [2] 82 bc [2] c5 ad [2] 8b a1 [2] 87 ab [2] 90 a0 [2] 8b ee [2] b6 }

  condition:
    any of them
}