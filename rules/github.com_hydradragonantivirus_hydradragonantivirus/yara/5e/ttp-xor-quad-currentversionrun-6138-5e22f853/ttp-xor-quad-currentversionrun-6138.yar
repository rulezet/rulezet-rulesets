rule TTP_XOR_QUAD_CurrentVersionRun_6138 {
  strings:
    $key_6138 = { 32 57 [2] 16 59 [2] 3d 75 [2] 13 57 [2] 07 4c [2] 08 56 [2] 16 4b [2] 14 4a [2] 0f 4c [2] 13 4b [2] 0f 64 }

  condition:
    any of them
}