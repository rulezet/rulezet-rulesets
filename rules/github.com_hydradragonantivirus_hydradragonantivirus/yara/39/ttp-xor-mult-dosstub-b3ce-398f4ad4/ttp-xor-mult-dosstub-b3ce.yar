rule TTP_XOR_MULT_DOSStub_b3ce {
  strings:
    $key_b3ce = { e7 a6 [2] 93 be [2] d4 bc [2] 93 ad [2] dd a1 [2] d1 ab [2] c6 a0 [2] dd ee [2] e0 }

  condition:
    any of them
}