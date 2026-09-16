rule TTP_XOR_MULT_DOSStub_e3d5 {
  strings:
    $key_e3d5 = { b7 bd [2] c3 a5 [2] 84 a7 [2] c3 b6 [2] 8d ba [2] 81 b0 [2] 96 bb [2] 8d f5 [2] b0 }

  condition:
    any of them
}