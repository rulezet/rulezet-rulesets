rule TTP_XOR_QUAD_CurrentVersionRun_6149 {
  strings:
    $key_6149 = { 32 26 [2] 16 28 [2] 3d 04 [2] 13 26 [2] 07 3d [2] 08 27 [2] 16 3a [2] 14 3b [2] 0f 3d [2] 13 3a [2] 0f 15 }

  condition:
    any of them
}