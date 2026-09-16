rule TTP_XOR_QUAD_CurrentVersionRun_7142 {
  strings:
    $key_7142 = { 22 2d [2] 06 23 [2] 2d 0f [2] 03 2d [2] 17 36 [2] 18 2c [2] 06 31 [2] 04 30 [2] 1f 36 [2] 03 31 [2] 1f 1e }

  condition:
    any of them
}