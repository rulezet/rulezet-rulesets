rule TTP_XOR_QUAD_CurrentVersionRun_7853 {
  strings:
    $key_7853 = { 2b 3c [2] 0f 32 [2] 24 1e [2] 0a 3c [2] 1e 27 [2] 11 3d [2] 0f 20 [2] 0d 21 [2] 16 27 [2] 0a 20 [2] 16 0f }

  condition:
    any of them
}