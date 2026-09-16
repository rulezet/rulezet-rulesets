rule TTP_XOR_QUAD_CurrentVersionRun_1e61 {
  strings:
    $key_1e61 = { 4d 0e [2] 69 00 [2] 42 2c [2] 6c 0e [2] 78 15 [2] 77 0f [2] 69 12 [2] 6b 13 [2] 70 15 [2] 6c 12 [2] 70 3d }

  condition:
    any of them
}