rule TTP_XOR_QUAD_CurrentVersionRun_7e74 {
  strings:
    $key_7e74 = { 2d 1b [2] 09 15 [2] 22 39 [2] 0c 1b [2] 18 00 [2] 17 1a [2] 09 07 [2] 0b 06 [2] 10 00 [2] 0c 07 [2] 10 28 }

  condition:
    any of them
}