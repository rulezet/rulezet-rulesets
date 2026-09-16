rule TTP_XOR_QUAD_CurrentVersionRun_4b70 {
  strings:
    $key_4b70 = { 18 1f [2] 3c 11 [2] 17 3d [2] 39 1f [2] 2d 04 [2] 22 1e [2] 3c 03 [2] 3e 02 [2] 25 04 [2] 39 03 [2] 25 2c }

  condition:
    any of them
}