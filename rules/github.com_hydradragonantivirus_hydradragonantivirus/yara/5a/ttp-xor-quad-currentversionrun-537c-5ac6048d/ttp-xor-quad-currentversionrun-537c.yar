rule TTP_XOR_QUAD_CurrentVersionRun_537c {
  strings:
    $key_537c = { 00 13 [2] 24 1d [2] 0f 31 [2] 21 13 [2] 35 08 [2] 3a 12 [2] 24 0f [2] 26 0e [2] 3d 08 [2] 21 0f [2] 3d 20 }

  condition:
    any of them
}