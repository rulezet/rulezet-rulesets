rule TTP_XOR_QUAD_CurrentVersionRun_6861 {
  strings:
    $key_6861 = { 3b 0e [2] 1f 00 [2] 34 2c [2] 1a 0e [2] 0e 15 [2] 01 0f [2] 1f 12 [2] 1d 13 [2] 06 15 [2] 1a 12 [2] 06 3d }

  condition:
    any of them
}