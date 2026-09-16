rule TTP_XOR_QUAD_CurrentVersionRun_7a70 {
  strings:
    $key_7a70 = { 29 1f [2] 0d 11 [2] 26 3d [2] 08 1f [2] 1c 04 [2] 13 1e [2] 0d 03 [2] 0f 02 [2] 14 04 [2] 08 03 [2] 14 2c }

  condition:
    any of them
}