rule TTP_XOR_MULT_DOSStub_b6ce {
  strings:
    $key_b6ce = { e2 a6 [2] 96 be [2] d1 bc [2] 96 ad [2] d8 a1 [2] d4 ab [2] c3 a0 [2] d8 ee [2] e5 }

  condition:
    any of them
}