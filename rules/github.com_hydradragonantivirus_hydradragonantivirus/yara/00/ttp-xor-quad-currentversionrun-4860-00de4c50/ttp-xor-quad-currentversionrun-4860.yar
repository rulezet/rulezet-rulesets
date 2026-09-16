rule TTP_XOR_QUAD_CurrentVersionRun_4860 {
  strings:
    $key_4860 = { 1b 0f [2] 3f 01 [2] 14 2d [2] 3a 0f [2] 2e 14 [2] 21 0e [2] 3f 13 [2] 3d 12 [2] 26 14 [2] 3a 13 [2] 26 3c }

  condition:
    any of them
}