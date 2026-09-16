rule TTP_XOR_QUAD_CurrentVersionRun_7b42 {
  strings:
    $key_7b42 = { 28 2d [2] 0c 23 [2] 27 0f [2] 09 2d [2] 1d 36 [2] 12 2c [2] 0c 31 [2] 0e 30 [2] 15 36 [2] 09 31 [2] 15 1e }

  condition:
    any of them
}