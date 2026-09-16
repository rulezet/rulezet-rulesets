rule TTP_XOR_QUAD_CurrentVersionRun_1161 {
  strings:
    $key_1161 = { 42 0e [2] 66 00 [2] 4d 2c [2] 63 0e [2] 77 15 [2] 78 0f [2] 66 12 [2] 64 13 [2] 7f 15 [2] 63 12 [2] 7f 3d }

  condition:
    any of them
}