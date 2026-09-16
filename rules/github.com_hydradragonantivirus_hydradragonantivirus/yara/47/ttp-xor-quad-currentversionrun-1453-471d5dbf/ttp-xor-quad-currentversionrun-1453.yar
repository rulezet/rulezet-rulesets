rule TTP_XOR_QUAD_CurrentVersionRun_1453 {
  strings:
    $key_1453 = { 47 3c [2] 63 32 [2] 48 1e [2] 66 3c [2] 72 27 [2] 7d 3d [2] 63 20 [2] 61 21 [2] 7a 27 [2] 66 20 [2] 7a 0f }

  condition:
    any of them
}