rule TTP_XOR_QUAD_CurrentVersionRun_4f66 {
  strings:
    $key_4f66 = { 1c 09 [2] 38 07 [2] 13 2b [2] 3d 09 [2] 29 12 [2] 26 08 [2] 38 15 [2] 3a 14 [2] 21 12 [2] 3d 15 [2] 21 3a }

  condition:
    any of them
}