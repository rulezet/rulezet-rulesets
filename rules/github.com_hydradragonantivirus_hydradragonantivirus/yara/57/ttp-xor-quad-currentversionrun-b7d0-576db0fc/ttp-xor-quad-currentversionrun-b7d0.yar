rule TTP_XOR_QUAD_CurrentVersionRun_b7d0 {
  strings:
    $key_b7d0 = { e4 bf [2] c0 b1 [2] eb 9d [2] c5 bf [2] d1 a4 [2] de be [2] c0 a3 [2] c2 a2 [2] d9 a4 [2] c5 a3 [2] d9 8c }

  condition:
    any of them
}