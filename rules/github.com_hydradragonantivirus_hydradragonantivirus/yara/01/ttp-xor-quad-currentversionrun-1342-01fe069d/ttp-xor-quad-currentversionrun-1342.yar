rule TTP_XOR_QUAD_CurrentVersionRun_1342 {
  strings:
    $key_1342 = { 40 2d [2] 64 23 [2] 4f 0f [2] 61 2d [2] 75 36 [2] 7a 2c [2] 64 31 [2] 66 30 [2] 7d 36 [2] 61 31 [2] 7d 1e }

  condition:
    any of them
}