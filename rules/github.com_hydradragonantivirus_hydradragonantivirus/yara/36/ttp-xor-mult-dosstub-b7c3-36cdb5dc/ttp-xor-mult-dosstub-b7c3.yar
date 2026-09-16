rule TTP_XOR_MULT_DOSStub_b7c3 {
  strings:
    $key_b7c3 = { e3 ab [2] 97 b3 [2] d0 b1 [2] 97 a0 [2] d9 ac [2] d5 a6 [2] c2 ad [2] d9 e3 [2] e4 }

  condition:
    any of them
}