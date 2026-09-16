rule TTP_XOR_MULT_DOSStub_a1c3 {
  strings:
    $key_a1c3 = { f5 ab [2] 81 b3 [2] c6 b1 [2] 81 a0 [2] cf ac [2] c3 a6 [2] d4 ad [2] cf e3 [2] f2 }

  condition:
    any of them
}