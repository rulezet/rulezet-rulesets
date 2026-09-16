rule TTP_XOR_QUAD_CurrentVersionRun_7070 {
  strings:
    $key_7070 = { 23 1f [2] 07 11 [2] 2c 3d [2] 02 1f [2] 16 04 [2] 19 1e [2] 07 03 [2] 05 02 [2] 1e 04 [2] 02 03 [2] 1e 2c }

  condition:
    any of them
}