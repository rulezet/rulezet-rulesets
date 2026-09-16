rule TTP_XOR_QUAD_CurrentVersionRun_4870 {
  strings:
    $key_4870 = { 1b 1f [2] 3f 11 [2] 14 3d [2] 3a 1f [2] 2e 04 [2] 21 1e [2] 3f 03 [2] 3d 02 [2] 26 04 [2] 3a 03 [2] 26 2c }

  condition:
    any of them
}