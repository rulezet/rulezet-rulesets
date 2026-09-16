rule TTP_XOR_QUAD_CurrentVersionRun_7361 {
  strings:
    $key_7361 = { 20 0e [2] 04 00 [2] 2f 2c [2] 01 0e [2] 15 15 [2] 1a 0f [2] 04 12 [2] 06 13 [2] 1d 15 [2] 01 12 [2] 1d 3d }

  condition:
    any of them
}