rule TTP_XOR_MULT_DOSStub_a7c3 {
  strings:
    $key_a7c3 = { f3 ab [2] 87 b3 [2] c0 b1 [2] 87 a0 [2] c9 ac [2] c5 a6 [2] d2 ad [2] c9 e3 [2] f4 }

  condition:
    any of them
}