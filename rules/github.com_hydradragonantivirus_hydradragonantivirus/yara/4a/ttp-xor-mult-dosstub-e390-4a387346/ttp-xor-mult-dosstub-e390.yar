rule TTP_XOR_MULT_DOSStub_e390 {
  strings:
    $key_e390 = { b7 f8 [2] c3 e0 [2] 84 e2 [2] c3 f3 [2] 8d ff [2] 81 f5 [2] 96 fe [2] 8d b0 [2] b0 }

  condition:
    any of them
}