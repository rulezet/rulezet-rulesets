rule TTP_XOR_QUAD_CurrentVersionRun_5661 {
  strings:
    $key_5661 = { 05 0e [2] 21 00 [2] 0a 2c [2] 24 0e [2] 30 15 [2] 3f 0f [2] 21 12 [2] 23 13 [2] 38 15 [2] 24 12 [2] 38 3d }

  condition:
    any of them
}