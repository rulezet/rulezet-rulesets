rule TTP_XOR_QUAD_CurrentVersionRun_6139 {
  strings:
    $key_6139 = { 32 56 [2] 16 58 [2] 3d 74 [2] 13 56 [2] 07 4d [2] 08 57 [2] 16 4a [2] 14 4b [2] 0f 4d [2] 13 4a [2] 0f 65 }

  condition:
    any of them
}