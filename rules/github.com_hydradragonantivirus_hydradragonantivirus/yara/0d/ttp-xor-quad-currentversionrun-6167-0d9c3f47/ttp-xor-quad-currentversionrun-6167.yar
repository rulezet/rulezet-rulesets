rule TTP_XOR_QUAD_CurrentVersionRun_6167 {
  strings:
    $key_6167 = { 32 08 [2] 16 06 [2] 3d 2a [2] 13 08 [2] 07 13 [2] 08 09 [2] 16 14 [2] 14 15 [2] 0f 13 [2] 13 14 [2] 0f 3b }

  condition:
    any of them
}