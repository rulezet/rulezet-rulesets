rule TTP_XOR_QUAD_CurrentVersionRun_b3d9 {
  strings:
    $key_b3d9 = { e0 b6 [2] c4 b8 [2] ef 94 [2] c1 b6 [2] d5 ad [2] da b7 [2] c4 aa [2] c6 ab [2] dd ad [2] c1 aa [2] dd 85 }

  condition:
    any of them
}