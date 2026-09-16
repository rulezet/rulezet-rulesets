rule TTP_XOR_QUAD_CurrentVersionRun_7d25 {
  strings:
    $key_7d25 = { 2e 4a [2] 0a 44 [2] 21 68 [2] 0f 4a [2] 1b 51 [2] 14 4b [2] 0a 56 [2] 08 57 [2] 13 51 [2] 0f 56 [2] 13 79 }

  condition:
    any of them
}