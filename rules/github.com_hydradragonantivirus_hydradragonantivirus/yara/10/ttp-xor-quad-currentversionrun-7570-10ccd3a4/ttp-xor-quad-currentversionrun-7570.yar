rule TTP_XOR_QUAD_CurrentVersionRun_7570 {
  strings:
    $key_7570 = { 26 1f [2] 02 11 [2] 29 3d [2] 07 1f [2] 13 04 [2] 1c 1e [2] 02 03 [2] 00 02 [2] 1b 04 [2] 07 03 [2] 1b 2c }

  condition:
    any of them
}