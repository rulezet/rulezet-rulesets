rule TTP_XOR_QUAD_CurrentVersionRun_5340 {
  strings:
    $key_5340 = { 00 2f [2] 24 21 [2] 0f 0d [2] 21 2f [2] 35 34 [2] 3a 2e [2] 24 33 [2] 26 32 [2] 3d 34 [2] 21 33 [2] 3d 1c }

  condition:
    any of them
}