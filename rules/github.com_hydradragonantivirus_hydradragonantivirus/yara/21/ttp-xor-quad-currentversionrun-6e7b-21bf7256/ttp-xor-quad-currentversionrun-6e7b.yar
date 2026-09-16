rule TTP_XOR_QUAD_CurrentVersionRun_6e7b {
  strings:
    $key_6e7b = { 3d 14 [2] 19 1a [2] 32 36 [2] 1c 14 [2] 08 0f [2] 07 15 [2] 19 08 [2] 1b 09 [2] 00 0f [2] 1c 08 [2] 00 27 }

  condition:
    any of them
}