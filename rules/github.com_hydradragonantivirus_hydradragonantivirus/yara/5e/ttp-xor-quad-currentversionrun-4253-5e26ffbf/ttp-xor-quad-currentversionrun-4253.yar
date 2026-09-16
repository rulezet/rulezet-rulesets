rule TTP_XOR_QUAD_CurrentVersionRun_4253 {
  strings:
    $key_4253 = { 11 3c [2] 35 32 [2] 1e 1e [2] 30 3c [2] 24 27 [2] 2b 3d [2] 35 20 [2] 37 21 [2] 2c 27 [2] 30 20 [2] 2c 0f }

  condition:
    any of them
}