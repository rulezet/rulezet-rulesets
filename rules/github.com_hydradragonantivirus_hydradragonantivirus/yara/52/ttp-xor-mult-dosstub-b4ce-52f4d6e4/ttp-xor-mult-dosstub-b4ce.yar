rule TTP_XOR_MULT_DOSStub_b4ce {
  strings:
    $key_b4ce = { e0 a6 [2] 94 be [2] d3 bc [2] 94 ad [2] da a1 [2] d6 ab [2] c1 a0 [2] da ee [2] e7 }

  condition:
    any of them
}