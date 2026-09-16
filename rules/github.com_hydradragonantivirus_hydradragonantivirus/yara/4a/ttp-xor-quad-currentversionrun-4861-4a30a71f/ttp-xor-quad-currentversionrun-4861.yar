rule TTP_XOR_QUAD_CurrentVersionRun_4861 {
  strings:
    $key_4861 = { 1b 0e [2] 3f 00 [2] 14 2c [2] 3a 0e [2] 2e 15 [2] 21 0f [2] 3f 12 [2] 3d 13 [2] 26 15 [2] 3a 12 [2] 26 3d }

  condition:
    any of them
}