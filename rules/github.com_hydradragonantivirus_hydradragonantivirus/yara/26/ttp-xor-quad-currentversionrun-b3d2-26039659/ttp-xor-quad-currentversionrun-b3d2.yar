rule TTP_XOR_QUAD_CurrentVersionRun_b3d2 {
  strings:
    $key_b3d2 = { e0 bd [2] c4 b3 [2] ef 9f [2] c1 bd [2] d5 a6 [2] da bc [2] c4 a1 [2] c6 a0 [2] dd a6 [2] c1 a1 [2] dd 8e }

  condition:
    any of them
}