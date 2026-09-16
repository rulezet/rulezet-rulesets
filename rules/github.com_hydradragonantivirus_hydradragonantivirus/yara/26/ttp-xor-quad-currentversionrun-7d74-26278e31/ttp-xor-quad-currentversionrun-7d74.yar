rule TTP_XOR_QUAD_CurrentVersionRun_7d74 {
  strings:
    $key_7d74 = { 2e 1b [2] 0a 15 [2] 21 39 [2] 0f 1b [2] 1b 00 [2] 14 1a [2] 0a 07 [2] 08 06 [2] 13 00 [2] 0f 07 [2] 13 28 }

  condition:
    any of them
}