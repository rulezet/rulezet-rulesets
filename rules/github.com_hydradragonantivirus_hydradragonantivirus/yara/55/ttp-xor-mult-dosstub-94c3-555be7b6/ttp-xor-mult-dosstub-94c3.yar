rule TTP_XOR_MULT_DOSStub_94c3 {
  strings:
    $key_94c3 = { c0 ab [2] b4 b3 [2] f3 b1 [2] b4 a0 [2] fa ac [2] f6 a6 [2] e1 ad [2] fa e3 [2] c7 }

  condition:
    any of them
}