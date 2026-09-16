rule TTP_XOR_QUAD_CurrentVersionRun_5953 {
  strings:
    $key_5953 = { 0a 3c [2] 2e 32 [2] 05 1e [2] 2b 3c [2] 3f 27 [2] 30 3d [2] 2e 20 [2] 2c 21 [2] 37 27 [2] 2b 20 [2] 37 0f }

  condition:
    any of them
}