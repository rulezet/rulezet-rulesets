rule TTP_XOR_QUAD_CurrentVersionRun_5142 {
  strings:
    $key_5142 = { 02 2d [2] 26 23 [2] 0d 0f [2] 23 2d [2] 37 36 [2] 38 2c [2] 26 31 [2] 24 30 [2] 3f 36 [2] 23 31 [2] 3f 1e }

  condition:
    any of them
}