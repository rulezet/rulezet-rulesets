rule TTP_XOR_QUAD_CurrentVersionRun_0342 {
  strings:
    $key_0342 = { 50 2d [2] 74 23 [2] 5f 0f [2] 71 2d [2] 65 36 [2] 6a 2c [2] 74 31 [2] 76 30 [2] 6d 36 [2] 71 31 [2] 6d 1e }

  condition:
    any of them
}