rule TTP_XOR_MULT_DOSStub_b6c3 {
  strings:
    $key_b6c3 = { e2 ab [2] 96 b3 [2] d1 b1 [2] 96 a0 [2] d8 ac [2] d4 a6 [2] c3 ad [2] d8 e3 [2] e5 }

  condition:
    any of them
}