rule TTP_XOR_QUAD_CurrentVersionRun_7e70 {
  strings:
    $key_7e70 = { 2d 1f [2] 09 11 [2] 22 3d [2] 0c 1f [2] 18 04 [2] 17 1e [2] 09 03 [2] 0b 02 [2] 10 04 [2] 0c 03 [2] 10 2c }

  condition:
    any of them
}