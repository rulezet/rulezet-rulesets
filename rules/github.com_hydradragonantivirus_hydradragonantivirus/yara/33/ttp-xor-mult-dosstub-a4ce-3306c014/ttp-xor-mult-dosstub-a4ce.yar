rule TTP_XOR_MULT_DOSStub_a4ce {
  strings:
    $key_a4ce = { f0 a6 [2] 84 be [2] c3 bc [2] 84 ad [2] ca a1 [2] c6 ab [2] d1 a0 [2] ca ee [2] f7 }

  condition:
    any of them
}