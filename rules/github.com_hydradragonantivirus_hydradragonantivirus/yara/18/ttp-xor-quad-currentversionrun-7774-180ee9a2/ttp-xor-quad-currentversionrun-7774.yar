rule TTP_XOR_QUAD_CurrentVersionRun_7774 {
  strings:
    $key_7774 = { 24 1b [2] 00 15 [2] 2b 39 [2] 05 1b [2] 11 00 [2] 1e 1a [2] 00 07 [2] 02 06 [2] 19 00 [2] 05 07 [2] 19 28 }

  condition:
    any of them
}