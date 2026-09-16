rule TTP_XOR_MULT_DOSStub_e3c8 {
  strings:
    $key_e3c8 = { b7 a0 [2] c3 b8 [2] 84 ba [2] c3 ab [2] 8d a7 [2] 81 ad [2] 96 a6 [2] 8d e8 [2] b0 }

  condition:
    any of them
}