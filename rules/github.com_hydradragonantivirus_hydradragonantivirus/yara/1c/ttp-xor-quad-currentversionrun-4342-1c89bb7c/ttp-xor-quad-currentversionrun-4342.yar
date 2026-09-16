rule TTP_XOR_QUAD_CurrentVersionRun_4342 {
  strings:
    $key_4342 = { 10 2d [2] 34 23 [2] 1f 0f [2] 31 2d [2] 25 36 [2] 2a 2c [2] 34 31 [2] 36 30 [2] 2d 36 [2] 31 31 [2] 2d 1e }

  condition:
    any of them
}