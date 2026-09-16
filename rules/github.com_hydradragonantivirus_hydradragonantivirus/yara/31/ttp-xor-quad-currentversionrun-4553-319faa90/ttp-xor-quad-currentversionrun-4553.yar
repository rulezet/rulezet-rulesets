rule TTP_XOR_QUAD_CurrentVersionRun_4553 {
  strings:
    $key_4553 = { 16 3c [2] 32 32 [2] 19 1e [2] 37 3c [2] 23 27 [2] 2c 3d [2] 32 20 [2] 30 21 [2] 2b 27 [2] 37 20 [2] 2b 0f }

  condition:
    any of them
}