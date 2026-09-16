rule TTP_XOR_QUAD_CurrentVersionRun_b7f3 {
  strings:
    $key_b7f3 = { e4 9c [2] c0 92 [2] eb be [2] c5 9c [2] d1 87 [2] de 9d [2] c0 80 [2] c2 81 [2] d9 87 [2] c5 80 [2] d9 af }

  condition:
    any of them
}