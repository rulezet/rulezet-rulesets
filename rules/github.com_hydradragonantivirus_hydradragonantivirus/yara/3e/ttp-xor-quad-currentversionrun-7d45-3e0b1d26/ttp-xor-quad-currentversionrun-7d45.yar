rule TTP_XOR_QUAD_CurrentVersionRun_7d45 {
  strings:
    $key_7d45 = { 2e 2a [2] 0a 24 [2] 21 08 [2] 0f 2a [2] 1b 31 [2] 14 2b [2] 0a 36 [2] 08 37 [2] 13 31 [2] 0f 36 [2] 13 19 }

  condition:
    any of them
}