rule TTP_XOR_QUAD_CurrentVersionRun_6125 {
  strings:
    $key_6125 = { 32 4a [2] 16 44 [2] 3d 68 [2] 13 4a [2] 07 51 [2] 08 4b [2] 16 56 [2] 14 57 [2] 0f 51 [2] 13 56 [2] 0f 79 }

  condition:
    any of them
}