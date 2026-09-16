rule TTP_XOR_MULT_DOSStub_e3c3 {
  strings:
    $key_e3c3 = { b7 ab [2] c3 b3 [2] 84 b1 [2] c3 a0 [2] 8d ac [2] 81 a6 [2] 96 ad [2] 8d e3 [2] b0 }

  condition:
    any of them
}