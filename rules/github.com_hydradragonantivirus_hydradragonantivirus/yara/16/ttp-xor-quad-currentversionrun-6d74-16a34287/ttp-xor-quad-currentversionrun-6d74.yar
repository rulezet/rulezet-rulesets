rule TTP_XOR_QUAD_CurrentVersionRun_6d74 {
  strings:
    $key_6d74 = { 3e 1b [2] 1a 15 [2] 31 39 [2] 1f 1b [2] 0b 00 [2] 04 1a [2] 1a 07 [2] 18 06 [2] 03 00 [2] 1f 07 [2] 03 28 }

  condition:
    any of them
}