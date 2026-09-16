rule TTP_XOR_QUAD_CurrentVersionRun_1870 {
  strings:
    $key_1870 = { 4b 1f [2] 6f 11 [2] 44 3d [2] 6a 1f [2] 7e 04 [2] 71 1e [2] 6f 03 [2] 6d 02 [2] 76 04 [2] 6a 03 [2] 76 2c }

  condition:
    any of them
}