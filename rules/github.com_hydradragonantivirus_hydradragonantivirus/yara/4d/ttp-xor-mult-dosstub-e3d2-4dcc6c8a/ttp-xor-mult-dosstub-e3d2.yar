rule TTP_XOR_MULT_DOSStub_e3d2 {
  strings:
    $key_e3d2 = { b7 ba [2] c3 a2 [2] 84 a0 [2] c3 b1 [2] 8d bd [2] 81 b7 [2] 96 bc [2] 8d f2 [2] b0 }

  condition:
    any of them
}