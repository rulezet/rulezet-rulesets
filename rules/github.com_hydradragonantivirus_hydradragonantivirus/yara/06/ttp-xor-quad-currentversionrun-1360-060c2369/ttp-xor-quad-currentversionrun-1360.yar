rule TTP_XOR_QUAD_CurrentVersionRun_1360 {
  strings:
    $key_1360 = { 40 0f [2] 64 01 [2] 4f 2d [2] 61 0f [2] 75 14 [2] 7a 0e [2] 64 13 [2] 66 12 [2] 7d 14 [2] 61 13 [2] 7d 3c }

  condition:
    any of them
}