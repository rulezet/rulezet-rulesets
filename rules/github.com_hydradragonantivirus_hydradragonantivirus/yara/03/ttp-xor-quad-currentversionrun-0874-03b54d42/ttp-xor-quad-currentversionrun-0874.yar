rule TTP_XOR_QUAD_CurrentVersionRun_0874 {
  strings:
    $key_0874 = { 5b 1b [2] 7f 15 [2] 54 39 [2] 7a 1b [2] 6e 00 [2] 61 1a [2] 7f 07 [2] 7d 06 [2] 66 00 [2] 7a 07 [2] 66 28 }

  condition:
    any of them
}