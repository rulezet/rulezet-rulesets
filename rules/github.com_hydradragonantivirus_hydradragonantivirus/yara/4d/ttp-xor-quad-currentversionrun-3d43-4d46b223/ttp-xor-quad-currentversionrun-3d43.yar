rule TTP_XOR_QUAD_CurrentVersionRun_3d43 {
  strings:
    $key_3d43 = { 6e 2c [2] 4a 22 [2] 61 0e [2] 4f 2c [2] 5b 37 [2] 54 2d [2] 4a 30 [2] 48 31 [2] 53 37 [2] 4f 30 [2] 53 1f }

  condition:
    any of them
}