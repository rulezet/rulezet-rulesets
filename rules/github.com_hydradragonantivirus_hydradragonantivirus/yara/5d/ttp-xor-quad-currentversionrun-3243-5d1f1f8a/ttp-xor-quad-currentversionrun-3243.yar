rule TTP_XOR_QUAD_CurrentVersionRun_3243 {
  strings:
    $key_3243 = { 61 2c [2] 45 22 [2] 6e 0e [2] 40 2c [2] 54 37 [2] 5b 2d [2] 45 30 [2] 47 31 [2] 5c 37 [2] 40 30 [2] 5c 1f }

  condition:
    any of them
}