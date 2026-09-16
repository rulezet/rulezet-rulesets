rule TTP_XOR_QUAD_CurrentVersionRun_3670 {
  strings:
    $key_3670 = { 65 1f [2] 41 11 [2] 6a 3d [2] 44 1f [2] 50 04 [2] 5f 1e [2] 41 03 [2] 43 02 [2] 58 04 [2] 44 03 [2] 58 2c }

  condition:
    any of them
}