rule TTP_XOR_QUAD_CurrentVersionRun_1774 {
  strings:
    $key_1774 = { 44 1b [2] 60 15 [2] 4b 39 [2] 65 1b [2] 71 00 [2] 7e 1a [2] 60 07 [2] 62 06 [2] 79 00 [2] 65 07 [2] 79 28 }

  condition:
    any of them
}