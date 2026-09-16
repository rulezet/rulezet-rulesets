rule TTP_XOR_QUAD_CurrentVersionRun_e7c0 {
  strings:
    $key_e7c0 = { b4 af [2] 90 a1 [2] bb 8d [2] 95 af [2] 81 b4 [2] 8e ae [2] 90 b3 [2] 92 b2 [2] 89 b4 [2] 95 b3 [2] 89 9c }

  condition:
    any of them
}