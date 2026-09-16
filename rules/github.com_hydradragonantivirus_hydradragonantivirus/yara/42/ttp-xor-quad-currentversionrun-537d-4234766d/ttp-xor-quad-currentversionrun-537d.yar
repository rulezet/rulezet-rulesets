rule TTP_XOR_QUAD_CurrentVersionRun_537d {
  strings:
    $key_537d = { 00 12 [2] 24 1c [2] 0f 30 [2] 21 12 [2] 35 09 [2] 3a 13 [2] 24 0e [2] 26 0f [2] 3d 09 [2] 21 0e [2] 3d 21 }

  condition:
    any of them
}