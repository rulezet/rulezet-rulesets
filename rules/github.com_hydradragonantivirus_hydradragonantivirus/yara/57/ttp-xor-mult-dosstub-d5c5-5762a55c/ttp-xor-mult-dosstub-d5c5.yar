rule TTP_XOR_MULT_DOSStub_d5c5 {
  strings:
    $key_d5c5 = { 81 ad [2] f5 b5 [2] b2 b7 [2] f5 a6 [2] bb aa [2] b7 a0 [2] a0 ab [2] bb e5 [2] 86 }

  condition:
    any of them
}