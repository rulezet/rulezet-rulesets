rule TTP_XOR_QUAD_CurrentVersionRun_7b70 {
  strings:
    $key_7b70 = { 28 1f [2] 0c 11 [2] 27 3d [2] 09 1f [2] 1d 04 [2] 12 1e [2] 0c 03 [2] 0e 02 [2] 15 04 [2] 09 03 [2] 15 2c }

  condition:
    any of them
}