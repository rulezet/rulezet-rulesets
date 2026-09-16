rule TTP_XOR_QUAD_CurrentVersionRun_5e53 {
  strings:
    $key_5e53 = { 0d 3c [2] 29 32 [2] 02 1e [2] 2c 3c [2] 38 27 [2] 37 3d [2] 29 20 [2] 2b 21 [2] 30 27 [2] 2c 20 [2] 30 0f }

  condition:
    any of them
}