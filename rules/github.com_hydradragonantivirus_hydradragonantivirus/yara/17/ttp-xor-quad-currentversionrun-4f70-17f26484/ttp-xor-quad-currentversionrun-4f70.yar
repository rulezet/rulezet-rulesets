rule TTP_XOR_QUAD_CurrentVersionRun_4f70 {
  strings:
    $key_4f70 = { 1c 1f [2] 38 11 [2] 13 3d [2] 3d 1f [2] 29 04 [2] 26 1e [2] 38 03 [2] 3a 02 [2] 21 04 [2] 3d 03 [2] 21 2c }

  condition:
    any of them
}