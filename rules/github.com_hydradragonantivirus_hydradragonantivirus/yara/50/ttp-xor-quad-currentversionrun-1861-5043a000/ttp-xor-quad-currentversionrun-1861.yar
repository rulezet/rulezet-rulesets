rule TTP_XOR_QUAD_CurrentVersionRun_1861 {
  strings:
    $key_1861 = { 4b 0e [2] 6f 00 [2] 44 2c [2] 6a 0e [2] 7e 15 [2] 71 0f [2] 6f 12 [2] 6d 13 [2] 76 15 [2] 6a 12 [2] 76 3d }

  condition:
    any of them
}