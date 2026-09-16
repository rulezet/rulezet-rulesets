rule TTP_XOR_QUAD_CurrentVersionRun_0161 {
  strings:
    $key_0161 = { 52 0e [2] 76 00 [2] 5d 2c [2] 73 0e [2] 67 15 [2] 68 0f [2] 76 12 [2] 74 13 [2] 6f 15 [2] 73 12 [2] 6f 3d }

  condition:
    any of them
}