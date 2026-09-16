rule TTP_XOR_MULT_DOSStub_b480 {
  strings:
    $key_b480 = { e0 e8 [2] 94 f0 [2] d3 f2 [2] 94 e3 [2] da ef [2] d6 e5 [2] c1 ee [2] da a0 [2] e7 }

  condition:
    any of them
}