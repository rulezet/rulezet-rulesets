rule TTP_XOR_QUAD_CurrentVersionRun_b4d0 {
  strings:
    $key_b4d0 = { e7 bf [2] c3 b1 [2] e8 9d [2] c6 bf [2] d2 a4 [2] dd be [2] c3 a3 [2] c1 a2 [2] da a4 [2] c6 a3 [2] da 8c }

  condition:
    any of them
}