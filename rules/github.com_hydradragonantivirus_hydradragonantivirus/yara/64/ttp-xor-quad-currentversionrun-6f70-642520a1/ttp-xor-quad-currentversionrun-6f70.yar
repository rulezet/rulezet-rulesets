rule TTP_XOR_QUAD_CurrentVersionRun_6f70 {
  strings:
    $key_6f70 = { 3c 1f [2] 18 11 [2] 33 3d [2] 1d 1f [2] 09 04 [2] 06 1e [2] 18 03 [2] 1a 02 [2] 01 04 [2] 1d 03 [2] 01 2c }

  condition:
    any of them
}