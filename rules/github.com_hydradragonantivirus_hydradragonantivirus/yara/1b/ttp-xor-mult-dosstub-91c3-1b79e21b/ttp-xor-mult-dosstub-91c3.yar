rule TTP_XOR_MULT_DOSStub_91c3 {
  strings:
    $key_91c3 = { c5 ab [2] b1 b3 [2] f6 b1 [2] b1 a0 [2] ff ac [2] f3 a6 [2] e4 ad [2] ff e3 [2] c2 }

  condition:
    any of them
}