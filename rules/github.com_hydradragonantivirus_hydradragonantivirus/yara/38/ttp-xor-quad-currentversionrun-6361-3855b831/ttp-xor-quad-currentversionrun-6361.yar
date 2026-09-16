rule TTP_XOR_QUAD_CurrentVersionRun_6361 {
  strings:
    $key_6361 = { 30 0e [2] 14 00 [2] 3f 2c [2] 11 0e [2] 05 15 [2] 0a 0f [2] 14 12 [2] 16 13 [2] 0d 15 [2] 11 12 [2] 0d 3d }

  condition:
    any of them
}