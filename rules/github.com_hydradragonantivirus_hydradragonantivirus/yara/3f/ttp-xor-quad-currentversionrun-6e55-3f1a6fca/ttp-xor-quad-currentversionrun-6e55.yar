rule TTP_XOR_QUAD_CurrentVersionRun_6e55 {
  strings:
    $key_6e55 = { 3d 3a [2] 19 34 [2] 32 18 [2] 1c 3a [2] 08 21 [2] 07 3b [2] 19 26 [2] 1b 27 [2] 00 21 [2] 1c 26 [2] 00 09 }

  condition:
    any of them
}