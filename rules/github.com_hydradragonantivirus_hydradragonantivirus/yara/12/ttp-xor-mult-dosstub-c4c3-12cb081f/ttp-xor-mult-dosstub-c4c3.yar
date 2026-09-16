rule TTP_XOR_MULT_DOSStub_c4c3 {
  strings:
    $key_c4c3 = { 90 ab [2] e4 b3 [2] a3 b1 [2] e4 a0 [2] aa ac [2] a6 a6 [2] b1 ad [2] aa e3 [2] 97 }

  condition:
    any of them
}