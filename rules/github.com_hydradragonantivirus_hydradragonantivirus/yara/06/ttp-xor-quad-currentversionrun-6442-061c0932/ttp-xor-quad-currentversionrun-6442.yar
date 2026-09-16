rule TTP_XOR_QUAD_CurrentVersionRun_6442 {
  strings:
    $key_6442 = { 37 2d [2] 13 23 [2] 38 0f [2] 16 2d [2] 02 36 [2] 0d 2c [2] 13 31 [2] 11 30 [2] 0a 36 [2] 16 31 [2] 0a 1e }

  condition:
    any of them
}