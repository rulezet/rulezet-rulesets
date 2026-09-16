rule TTP_XOR_QUAD_CurrentVersionRun_3b70 {
  strings:
    $key_3b70 = { 68 1f [2] 4c 11 [2] 67 3d [2] 49 1f [2] 5d 04 [2] 52 1e [2] 4c 03 [2] 4e 02 [2] 55 04 [2] 49 03 [2] 55 2c }

  condition:
    any of them
}