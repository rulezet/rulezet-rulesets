rule TTP_XOR_QUAD_CurrentVersionRun_7270 {
  strings:
    $key_7270 = { 21 1f [2] 05 11 [2] 2e 3d [2] 00 1f [2] 14 04 [2] 1b 1e [2] 05 03 [2] 07 02 [2] 1c 04 [2] 00 03 [2] 1c 2c }

  condition:
    any of them
}