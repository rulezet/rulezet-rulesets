rule TTP_XOR_QUAD_CurrentVersionRun_6157 {
  strings:
    $key_6157 = { 32 38 [2] 16 36 [2] 3d 1a [2] 13 38 [2] 07 23 [2] 08 39 [2] 16 24 [2] 14 25 [2] 0f 23 [2] 13 24 [2] 0f 0b }

  condition:
    any of them
}