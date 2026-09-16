rule TTP_XOR_QUAD_CurrentVersionRun_6e17 {
  strings:
    $key_6e17 = { 3d 78 [2] 19 76 [2] 32 5a [2] 1c 78 [2] 08 63 [2] 07 79 [2] 19 64 [2] 1b 65 [2] 00 63 [2] 1c 64 [2] 00 4b }

  condition:
    any of them
}