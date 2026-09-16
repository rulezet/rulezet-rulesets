rule TTP_XOR_QUAD_CurrentVersionRun_7d19 {
  strings:
    $key_7d19 = { 2e 76 [2] 0a 78 [2] 21 54 [2] 0f 76 [2] 1b 6d [2] 14 77 [2] 0a 6a [2] 08 6b [2] 13 6d [2] 0f 6a [2] 13 45 }

  condition:
    any of them
}