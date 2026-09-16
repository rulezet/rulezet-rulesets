rule TTP_XOR_QUAD_CurrentVersionRun_4153 {
  strings:
    $key_4153 = { 12 3c [2] 36 32 [2] 1d 1e [2] 33 3c [2] 27 27 [2] 28 3d [2] 36 20 [2] 34 21 [2] 2f 27 [2] 33 20 [2] 2f 0f }

  condition:
    any of them
}