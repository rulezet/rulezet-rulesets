rule TTP_XOR_QUAD_CurrentVersionRun_5774 {
  strings:
    $key_5774 = { 04 1b [2] 20 15 [2] 0b 39 [2] 25 1b [2] 31 00 [2] 3e 1a [2] 20 07 [2] 22 06 [2] 39 00 [2] 25 07 [2] 39 28 }

  condition:
    any of them
}