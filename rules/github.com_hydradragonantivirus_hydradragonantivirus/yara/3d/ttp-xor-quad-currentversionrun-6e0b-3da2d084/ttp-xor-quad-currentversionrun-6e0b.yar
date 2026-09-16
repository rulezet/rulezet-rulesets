rule TTP_XOR_QUAD_CurrentVersionRun_6e0b {
  strings:
    $key_6e0b = { 3d 64 [2] 19 6a [2] 32 46 [2] 1c 64 [2] 08 7f [2] 07 65 [2] 19 78 [2] 1b 79 [2] 00 7f [2] 1c 78 [2] 00 57 }

  condition:
    any of them
}