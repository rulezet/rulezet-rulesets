rule TTP_XOR_MULT_DOSStub_a5ce {
  strings:
    $key_a5ce = { f1 a6 [2] 85 be [2] c2 bc [2] 85 ad [2] cb a1 [2] c7 ab [2] d0 a0 [2] cb ee [2] f6 }

  condition:
    any of them
}