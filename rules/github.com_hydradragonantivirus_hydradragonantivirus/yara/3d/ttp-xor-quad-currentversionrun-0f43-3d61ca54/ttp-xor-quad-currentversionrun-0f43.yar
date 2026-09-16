rule TTP_XOR_QUAD_CurrentVersionRun_0f43 {
  strings:
    $key_0f43 = { 5c 2c [2] 78 22 [2] 53 0e [2] 7d 2c [2] 69 37 [2] 66 2d [2] 78 30 [2] 7a 31 [2] 61 37 [2] 7d 30 [2] 61 1f }

  condition:
    any of them
}