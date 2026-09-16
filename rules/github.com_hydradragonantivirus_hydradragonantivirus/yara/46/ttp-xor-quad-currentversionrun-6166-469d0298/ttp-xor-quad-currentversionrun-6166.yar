rule TTP_XOR_QUAD_CurrentVersionRun_6166 {
  strings:
    $key_6166 = { 32 09 [2] 16 07 [2] 3d 2b [2] 13 09 [2] 07 12 [2] 08 08 [2] 16 15 [2] 14 14 [2] 0f 12 [2] 13 15 [2] 0f 3a }

  condition:
    any of them
}