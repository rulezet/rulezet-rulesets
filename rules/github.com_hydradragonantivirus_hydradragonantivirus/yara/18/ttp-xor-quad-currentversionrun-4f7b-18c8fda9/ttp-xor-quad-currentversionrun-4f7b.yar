rule TTP_XOR_QUAD_CurrentVersionRun_4f7b {
  strings:
    $key_4f7b = { 1c 14 [2] 38 1a [2] 13 36 [2] 3d 14 [2] 29 0f [2] 26 15 [2] 38 08 [2] 3a 09 [2] 21 0f [2] 3d 08 [2] 21 27 }

  condition:
    any of them
}