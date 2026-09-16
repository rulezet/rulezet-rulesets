rule TTP_XOR_QUAD_CurrentVersionRun_6124 {
  strings:
    $key_6124 = { 32 4b [2] 16 45 [2] 3d 69 [2] 13 4b [2] 07 50 [2] 08 4a [2] 16 57 [2] 14 56 [2] 0f 50 [2] 13 57 [2] 0f 78 }

  condition:
    any of them
}