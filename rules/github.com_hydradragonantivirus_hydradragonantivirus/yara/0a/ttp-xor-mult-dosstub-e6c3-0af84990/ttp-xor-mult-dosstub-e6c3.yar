rule TTP_XOR_MULT_DOSStub_e6c3 {
  strings:
    $key_e6c3 = { b2 ab [2] c6 b3 [2] 81 b1 [2] c6 a0 [2] 88 ac [2] 84 a6 [2] 93 ad [2] 88 e3 [2] b5 }

  condition:
    any of them
}