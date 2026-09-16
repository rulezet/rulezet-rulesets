rule TTP_XOR_QUAD_CurrentVersionRun_5653 {
  strings:
    $key_5653 = { 05 3c [2] 21 32 [2] 0a 1e [2] 24 3c [2] 30 27 [2] 3f 3d [2] 21 20 [2] 23 21 [2] 38 27 [2] 24 20 [2] 38 0f }

  condition:
    any of them
}