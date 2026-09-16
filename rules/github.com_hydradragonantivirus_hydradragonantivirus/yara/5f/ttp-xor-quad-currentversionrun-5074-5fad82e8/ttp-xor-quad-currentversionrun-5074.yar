rule TTP_XOR_QUAD_CurrentVersionRun_5074 {
  strings:
    $key_5074 = { 03 1b [2] 27 15 [2] 0c 39 [2] 22 1b [2] 36 00 [2] 39 1a [2] 27 07 [2] 25 06 [2] 3e 00 [2] 22 07 [2] 3e 28 }

  condition:
    any of them
}