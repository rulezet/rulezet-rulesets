rule TTP_XOR_QUAD_CurrentVersionRun_4e53 {
  strings:
    $key_4e53 = { 1d 3c [2] 39 32 [2] 12 1e [2] 3c 3c [2] 28 27 [2] 27 3d [2] 39 20 [2] 3b 21 [2] 20 27 [2] 3c 20 [2] 20 0f }

  condition:
    any of them
}