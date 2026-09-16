rule TTP_XOR_QUAD_CurrentVersionRun_1f53 {
  strings:
    $key_1f53 = { 4c 3c [2] 68 32 [2] 43 1e [2] 6d 3c [2] 79 27 [2] 76 3d [2] 68 20 [2] 6a 21 [2] 71 27 [2] 6d 20 [2] 71 0f }

  condition:
    any of them
}