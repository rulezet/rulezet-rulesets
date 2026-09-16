rule TTP_XOR_QUAD_CurrentVersionRun_6159 {
  strings:
    $key_6159 = { 32 36 [2] 16 38 [2] 3d 14 [2] 13 36 [2] 07 2d [2] 08 37 [2] 16 2a [2] 14 2b [2] 0f 2d [2] 13 2a [2] 0f 05 }

  condition:
    any of them
}