rule TTP_XOR_QUAD_CurrentVersionRun_5b70 {
  strings:
    $key_5b70 = { 08 1f [2] 2c 11 [2] 07 3d [2] 29 1f [2] 3d 04 [2] 32 1e [2] 2c 03 [2] 2e 02 [2] 35 04 [2] 29 03 [2] 35 2c }

  condition:
    any of them
}