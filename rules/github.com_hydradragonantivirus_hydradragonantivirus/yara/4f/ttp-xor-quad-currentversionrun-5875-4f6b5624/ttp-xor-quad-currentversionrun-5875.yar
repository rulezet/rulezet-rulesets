rule TTP_XOR_QUAD_CurrentVersionRun_5875 {
  strings:
    $key_5875 = { 0b 1a [2] 2f 14 [2] 04 38 [2] 2a 1a [2] 3e 01 [2] 31 1b [2] 2f 06 [2] 2d 07 [2] 36 01 [2] 2a 06 [2] 36 29 }

  condition:
    any of them
}