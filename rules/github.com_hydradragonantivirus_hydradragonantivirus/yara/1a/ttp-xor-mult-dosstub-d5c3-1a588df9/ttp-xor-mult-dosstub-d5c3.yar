rule TTP_XOR_MULT_DOSStub_d5c3 {
  strings:
    $key_d5c3 = { 81 ab [2] f5 b3 [2] b2 b1 [2] f5 a0 [2] bb ac [2] b7 a6 [2] a0 ad [2] bb e3 [2] 86 }

  condition:
    any of them
}