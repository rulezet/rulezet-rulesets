rule TTP_XOR_MULT_DOSStub_e7c3 {
  strings:
    $key_e7c3 = { b3 ab [2] c7 b3 [2] 80 b1 [2] c7 a0 [2] 89 ac [2] 85 a6 [2] 92 ad [2] 89 e3 [2] b4 }

  condition:
    any of them
}