rule TTP_XOR_QUAD_CurrentVersionRun_4142 {
  strings:
    $key_4142 = { 12 2d [2] 36 23 [2] 1d 0f [2] 33 2d [2] 27 36 [2] 28 2c [2] 36 31 [2] 34 30 [2] 2f 36 [2] 33 31 [2] 2f 1e }

  condition:
    any of them
}