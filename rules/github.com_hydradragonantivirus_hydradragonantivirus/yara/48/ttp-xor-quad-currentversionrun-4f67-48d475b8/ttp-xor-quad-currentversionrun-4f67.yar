rule TTP_XOR_QUAD_CurrentVersionRun_4f67 {
  strings:
    $key_4f67 = { 1c 08 [2] 38 06 [2] 13 2a [2] 3d 08 [2] 29 13 [2] 26 09 [2] 38 14 [2] 3a 15 [2] 21 13 [2] 3d 14 [2] 21 3b }

  condition:
    any of them
}