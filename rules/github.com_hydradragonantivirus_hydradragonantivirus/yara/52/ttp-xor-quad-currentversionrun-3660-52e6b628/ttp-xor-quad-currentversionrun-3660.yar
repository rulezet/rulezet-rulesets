rule TTP_XOR_QUAD_CurrentVersionRun_3660 {
  strings:
    $key_3660 = { 65 0f [2] 41 01 [2] 6a 2d [2] 44 0f [2] 50 14 [2] 5f 0e [2] 41 13 [2] 43 12 [2] 58 14 [2] 44 13 [2] 58 3c }

  condition:
    any of them
}