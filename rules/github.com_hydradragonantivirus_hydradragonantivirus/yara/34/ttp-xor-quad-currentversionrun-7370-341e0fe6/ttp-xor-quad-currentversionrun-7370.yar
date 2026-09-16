rule TTP_XOR_QUAD_CurrentVersionRun_7370 {
  strings:
    $key_7370 = { 20 1f [2] 04 11 [2] 2f 3d [2] 01 1f [2] 15 04 [2] 1a 1e [2] 04 03 [2] 06 02 [2] 1d 04 [2] 01 03 [2] 1d 2c }

  condition:
    any of them
}