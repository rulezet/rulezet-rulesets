rule TTP_XOR_MULT_DOSStub_92c3 {
  strings:
    $key_92c3 = { c6 ab [2] b2 b3 [2] f5 b1 [2] b2 a0 [2] fc ac [2] f0 a6 [2] e7 ad [2] fc e3 [2] c1 }

  condition:
    any of them
}