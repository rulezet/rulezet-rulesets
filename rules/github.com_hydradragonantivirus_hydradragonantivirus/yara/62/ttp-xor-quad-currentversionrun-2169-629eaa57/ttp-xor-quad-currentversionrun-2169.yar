rule TTP_XOR_QUAD_CurrentVersionRun_2169 {
  strings:
    $key_2169 = { 72 06 [2] 56 08 [2] 7d 24 [2] 53 06 [2] 47 1d [2] 48 07 [2] 56 1a [2] 54 1b [2] 4f 1d [2] 53 1a [2] 4f 35 }

  condition:
    any of them
}