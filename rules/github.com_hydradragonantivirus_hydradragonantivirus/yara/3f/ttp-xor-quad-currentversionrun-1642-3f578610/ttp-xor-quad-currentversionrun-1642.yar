rule TTP_XOR_QUAD_CurrentVersionRun_1642 {
  strings:
    $key_1642 = { 45 2d [2] 61 23 [2] 4a 0f [2] 64 2d [2] 70 36 [2] 7f 2c [2] 61 31 [2] 63 30 [2] 78 36 [2] 64 31 [2] 78 1e }

  condition:
    any of them
}