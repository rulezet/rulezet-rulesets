rule TTP_XOR_QUAD_CurrentVersionRun_3170 {
  strings:
    $key_3170 = { 62 1f [2] 46 11 [2] 6d 3d [2] 43 1f [2] 57 04 [2] 58 1e [2] 46 03 [2] 44 02 [2] 5f 04 [2] 43 03 [2] 5f 2c }

  condition:
    any of them
}