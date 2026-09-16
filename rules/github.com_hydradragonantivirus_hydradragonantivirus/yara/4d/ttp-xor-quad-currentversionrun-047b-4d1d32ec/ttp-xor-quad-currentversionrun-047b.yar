rule TTP_XOR_QUAD_CurrentVersionRun_047b {
  strings:
    $key_047b = { 57 14 [2] 73 1a [2] 58 36 [2] 76 14 [2] 62 0f [2] 6d 15 [2] 73 08 [2] 71 09 [2] 6a 0f [2] 76 08 [2] 6a 27 }

  condition:
    any of them
}