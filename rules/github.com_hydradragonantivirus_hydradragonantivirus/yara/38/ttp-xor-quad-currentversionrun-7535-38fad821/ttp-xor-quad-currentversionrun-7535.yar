rule TTP_XOR_QUAD_CurrentVersionRun_7535 {
  strings:
    $key_7535 = { 26 5a [2] 02 54 [2] 29 78 [2] 07 5a [2] 13 41 [2] 1c 5b [2] 02 46 [2] 00 47 [2] 1b 41 [2] 07 46 [2] 1b 69 }

  condition:
    any of them
}