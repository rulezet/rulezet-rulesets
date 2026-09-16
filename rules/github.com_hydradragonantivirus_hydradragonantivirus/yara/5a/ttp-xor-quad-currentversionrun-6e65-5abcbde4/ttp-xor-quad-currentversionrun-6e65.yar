rule TTP_XOR_QUAD_CurrentVersionRun_6e65 {
  strings:
    $key_6e65 = { 3d 0a [2] 19 04 [2] 32 28 [2] 1c 0a [2] 08 11 [2] 07 0b [2] 19 16 [2] 1b 17 [2] 00 11 [2] 1c 16 [2] 00 39 }

  condition:
    any of them
}