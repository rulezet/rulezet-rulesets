rule TTP_XOR_QUAD_CurrentVersionRun_3661 {
  strings:
    $key_3661 = { 65 0e [2] 41 00 [2] 6a 2c [2] 44 0e [2] 50 15 [2] 5f 0f [2] 41 12 [2] 43 13 [2] 58 15 [2] 44 12 [2] 58 3d }

  condition:
    any of them
}