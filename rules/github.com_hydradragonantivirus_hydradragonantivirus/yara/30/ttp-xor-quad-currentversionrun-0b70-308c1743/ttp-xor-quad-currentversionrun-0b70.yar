rule TTP_XOR_QUAD_CurrentVersionRun_0b70 {
  strings:
    $key_0b70 = { 58 1f [2] 7c 11 [2] 57 3d [2] 79 1f [2] 6d 04 [2] 62 1e [2] 7c 03 [2] 7e 02 [2] 65 04 [2] 79 03 [2] 65 2c }

  condition:
    any of them
}