rule TTP_XOR_QUAD_CurrentVersionRun_3153 {
  strings:
    $key_3153 = { 62 3c [2] 46 32 [2] 6d 1e [2] 43 3c [2] 57 27 [2] 58 3d [2] 46 20 [2] 44 21 [2] 5f 27 [2] 43 20 [2] 5f 0f }

  condition:
    any of them
}