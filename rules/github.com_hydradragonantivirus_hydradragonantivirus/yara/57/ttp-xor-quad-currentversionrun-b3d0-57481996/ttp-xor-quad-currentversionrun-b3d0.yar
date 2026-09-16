rule TTP_XOR_QUAD_CurrentVersionRun_b3d0 {
  strings:
    $key_b3d0 = { e0 bf [2] c4 b1 [2] ef 9d [2] c1 bf [2] d5 a4 [2] da be [2] c4 a3 [2] c6 a2 [2] dd a4 [2] c1 a3 [2] dd 8c }

  condition:
    any of them
}