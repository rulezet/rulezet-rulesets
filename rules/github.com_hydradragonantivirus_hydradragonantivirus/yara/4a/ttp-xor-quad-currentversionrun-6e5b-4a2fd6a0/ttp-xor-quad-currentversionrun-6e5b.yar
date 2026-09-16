rule TTP_XOR_QUAD_CurrentVersionRun_6e5b {
  strings:
    $key_6e5b = { 3d 34 [2] 19 3a [2] 32 16 [2] 1c 34 [2] 08 2f [2] 07 35 [2] 19 28 [2] 1b 29 [2] 00 2f [2] 1c 28 [2] 00 07 }

  condition:
    any of them
}