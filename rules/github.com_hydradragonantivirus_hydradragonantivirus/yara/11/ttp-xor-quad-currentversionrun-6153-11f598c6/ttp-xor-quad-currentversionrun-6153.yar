rule TTP_XOR_QUAD_CurrentVersionRun_6153 {
  strings:
    $key_6153 = { 32 3c [2] 16 32 [2] 3d 1e [2] 13 3c [2] 07 27 [2] 08 3d [2] 16 20 [2] 14 21 [2] 0f 27 [2] 13 20 [2] 0f 0f }

  condition:
    any of them
}