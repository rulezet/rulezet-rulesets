rule TTP_XOR_QUAD_CurrentVersionRun_6853 {
  strings:
    $key_6853 = { 3b 3c [2] 1f 32 [2] 34 1e [2] 1a 3c [2] 0e 27 [2] 01 3d [2] 1f 20 [2] 1d 21 [2] 06 27 [2] 1a 20 [2] 06 0f }

  condition:
    any of them
}