rule TTP_XOR_QUAD_CurrentVersionRun_e453 {
  strings:
    $key_e453 = { b7 3c [2] 93 32 [2] b8 1e [2] 96 3c [2] 82 27 [2] 8d 3d [2] 93 20 [2] 91 21 [2] 8a 27 [2] 96 20 [2] 8a 0f }

  condition:
    any of them
}