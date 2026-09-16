rule TTP_XOR_QUAD_CurrentVersionRun_3853 {
  strings:
    $key_3853 = { 6b 3c [2] 4f 32 [2] 64 1e [2] 4a 3c [2] 5e 27 [2] 51 3d [2] 4f 20 [2] 4d 21 [2] 56 27 [2] 4a 20 [2] 56 0f }

  condition:
    any of them
}