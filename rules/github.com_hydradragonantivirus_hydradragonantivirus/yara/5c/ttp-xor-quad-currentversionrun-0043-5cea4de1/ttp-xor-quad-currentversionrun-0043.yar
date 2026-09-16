rule TTP_XOR_QUAD_CurrentVersionRun_0043 {
  strings:
    $key_0043 = { 53 2c [2] 77 22 [2] 5c 0e [2] 72 2c [2] 66 37 [2] 69 2d [2] 77 30 [2] 75 31 [2] 6e 37 [2] 72 30 [2] 6e 1f }

  condition:
    any of them
}