rule TTP_XOR_QUAD_CurrentVersionRun_1e53 {
  strings:
    $key_1e53 = { 4d 3c [2] 69 32 [2] 42 1e [2] 6c 3c [2] 78 27 [2] 77 3d [2] 69 20 [2] 6b 21 [2] 70 27 [2] 6c 20 [2] 70 0f }

  condition:
    any of them
}