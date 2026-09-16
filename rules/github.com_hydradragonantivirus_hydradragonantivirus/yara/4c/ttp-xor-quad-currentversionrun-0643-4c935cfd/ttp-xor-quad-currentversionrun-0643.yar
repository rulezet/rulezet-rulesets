rule TTP_XOR_QUAD_CurrentVersionRun_0643 {
  strings:
    $key_0643 = { 55 2c [2] 71 22 [2] 5a 0e [2] 74 2c [2] 60 37 [2] 6f 2d [2] 71 30 [2] 73 31 [2] 68 37 [2] 74 30 [2] 68 1f }

  condition:
    any of them
}