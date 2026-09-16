rule TTP_XOR_QUAD_CurrentVersionRun_7160 {
  strings:
    $key_7160 = { 22 0f [2] 06 01 [2] 2d 2d [2] 03 0f [2] 17 14 [2] 18 0e [2] 06 13 [2] 04 12 [2] 1f 14 [2] 03 13 [2] 1f 3c }

  condition:
    any of them
}