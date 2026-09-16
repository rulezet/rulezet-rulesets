rule TTP_XOR_QUAD_CurrentVersionRun_4e70 {
  strings:
    $key_4e70 = { 1d 1f [2] 39 11 [2] 12 3d [2] 3c 1f [2] 28 04 [2] 27 1e [2] 39 03 [2] 3b 02 [2] 20 04 [2] 3c 03 [2] 20 2c }

  condition:
    any of them
}