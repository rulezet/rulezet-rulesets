rule TTP_XOR_QUAD_CurrentVersionRun_4043 {
  strings:
    $key_4043 = { 13 2c [2] 37 22 [2] 1c 0e [2] 32 2c [2] 26 37 [2] 29 2d [2] 37 30 [2] 35 31 [2] 2e 37 [2] 32 30 [2] 2e 1f }

  condition:
    any of them
}