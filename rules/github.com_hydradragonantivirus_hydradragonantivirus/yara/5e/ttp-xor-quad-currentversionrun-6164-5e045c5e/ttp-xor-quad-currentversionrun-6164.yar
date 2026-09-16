rule TTP_XOR_QUAD_CurrentVersionRun_6164 {
  strings:
    $key_6164 = { 32 0b [2] 16 05 [2] 3d 29 [2] 13 0b [2] 07 10 [2] 08 0a [2] 16 17 [2] 14 16 [2] 0f 10 [2] 13 17 [2] 0f 38 }

  condition:
    any of them
}