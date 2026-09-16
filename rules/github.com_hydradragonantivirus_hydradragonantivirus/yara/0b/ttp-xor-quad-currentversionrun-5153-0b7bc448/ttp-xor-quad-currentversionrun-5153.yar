rule TTP_XOR_QUAD_CurrentVersionRun_5153 {
  strings:
    $key_5153 = { 02 3c [2] 26 32 [2] 0d 1e [2] 23 3c [2] 37 27 [2] 38 3d [2] 26 20 [2] 24 21 [2] 3f 27 [2] 23 20 [2] 3f 0f }

  condition:
    any of them
}