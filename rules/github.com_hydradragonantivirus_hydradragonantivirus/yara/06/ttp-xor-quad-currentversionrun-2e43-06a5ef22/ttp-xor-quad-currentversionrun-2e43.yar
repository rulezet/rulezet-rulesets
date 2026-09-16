rule TTP_XOR_QUAD_CurrentVersionRun_2e43 {
  strings:
    $key_2e43 = { 7d 2c [2] 59 22 [2] 72 0e [2] 5c 2c [2] 48 37 [2] 47 2d [2] 59 30 [2] 5b 31 [2] 40 37 [2] 5c 30 [2] 40 1f }

  condition:
    any of them
}