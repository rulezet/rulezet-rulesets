rule TTP_XOR_QUAD_CurrentVersionRun_2153 {
  strings:
    $key_2153 = { 72 3c [2] 56 32 [2] 7d 1e [2] 53 3c [2] 47 27 [2] 48 3d [2] 56 20 [2] 54 21 [2] 4f 27 [2] 53 20 [2] 4f 0f }

  condition:
    any of them
}