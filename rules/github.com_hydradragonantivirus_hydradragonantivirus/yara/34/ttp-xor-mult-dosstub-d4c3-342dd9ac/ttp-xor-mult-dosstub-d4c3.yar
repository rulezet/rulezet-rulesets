rule TTP_XOR_MULT_DOSStub_d4c3 {
  strings:
    $key_d4c3 = { 80 ab [2] f4 b3 [2] b3 b1 [2] f4 a0 [2] ba ac [2] b6 a6 [2] a1 ad [2] ba e3 [2] 87 }

  condition:
    any of them
}