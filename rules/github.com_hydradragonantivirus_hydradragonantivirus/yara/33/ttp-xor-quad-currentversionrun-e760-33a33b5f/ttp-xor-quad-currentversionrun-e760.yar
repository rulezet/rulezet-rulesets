rule TTP_XOR_QUAD_CurrentVersionRun_e760 {
  strings:
    $key_e760 = { b4 0f [2] 90 01 [2] bb 2d [2] 95 0f [2] 81 14 [2] 8e 0e [2] 90 13 [2] 92 12 [2] 89 14 [2] 95 13 [2] 89 3c }

  condition:
    any of them
}