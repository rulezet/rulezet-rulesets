rule TTP_XOR_QUAD_CurrentVersionRun_4f53 {
  strings:
    $key_4f53 = { 1c 3c [2] 38 32 [2] 13 1e [2] 3d 3c [2] 29 27 [2] 26 3d [2] 38 20 [2] 3a 21 [2] 21 27 [2] 3d 20 [2] 21 0f }

  condition:
    any of them
}