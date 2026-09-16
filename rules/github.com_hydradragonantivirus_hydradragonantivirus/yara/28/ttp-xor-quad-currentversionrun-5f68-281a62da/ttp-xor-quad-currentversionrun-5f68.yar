rule TTP_XOR_QUAD_CurrentVersionRun_5f68 {
  strings:
    $key_5f68 = { 0c 07 [2] 28 09 [2] 03 25 [2] 2d 07 [2] 39 1c [2] 36 06 [2] 28 1b [2] 2a 1a [2] 31 1c [2] 2d 1b [2] 31 34 }

  condition:
    any of them
}