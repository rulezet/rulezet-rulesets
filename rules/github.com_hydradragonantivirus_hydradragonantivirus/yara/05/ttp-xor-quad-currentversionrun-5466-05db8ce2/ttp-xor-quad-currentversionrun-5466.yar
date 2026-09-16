rule TTP_XOR_QUAD_CurrentVersionRun_5466 {
  strings:
    $key_5466 = { 07 09 [2] 23 07 [2] 08 2b [2] 26 09 [2] 32 12 [2] 3d 08 [2] 23 15 [2] 21 14 [2] 3a 12 [2] 26 15 [2] 3a 3a }

  condition:
    any of them
}