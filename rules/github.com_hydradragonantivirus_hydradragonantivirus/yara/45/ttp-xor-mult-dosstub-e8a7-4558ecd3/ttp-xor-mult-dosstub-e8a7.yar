rule TTP_XOR_MULT_DOSStub_e8a7 {
  strings:
    $key_e8a7 = { bc cf [2] c8 d7 [2] 8f d5 [2] c8 c4 [2] 86 c8 [2] 8a c2 [2] 9d c9 [2] 86 87 [2] bb }

  condition:
    any of them
}