rule TTP_XOR_QUAD_CurrentVersionRun_5f53 {
  strings:
    $key_5f53 = { 0c 3c [2] 28 32 [2] 03 1e [2] 2d 3c [2] 39 27 [2] 36 3d [2] 28 20 [2] 2a 21 [2] 31 27 [2] 2d 20 [2] 31 0f }

  condition:
    any of them
}