rule TTP_XOR_QUAD_CurrentVersionRun_4f68 {
  strings:
    $key_4f68 = { 1c 07 [2] 38 09 [2] 13 25 [2] 3d 07 [2] 29 1c [2] 26 06 [2] 38 1b [2] 3a 1a [2] 21 1c [2] 3d 1b [2] 21 34 }

  condition:
    any of them
}