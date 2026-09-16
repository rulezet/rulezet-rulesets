rule TTP_XOR_QUAD_CurrentVersionRun_3a70 {
  strings:
    $key_3a70 = { 69 1f [2] 4d 11 [2] 66 3d [2] 48 1f [2] 5c 04 [2] 53 1e [2] 4d 03 [2] 4f 02 [2] 54 04 [2] 48 03 [2] 54 2c }

  condition:
    any of them
}