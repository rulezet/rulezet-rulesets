rule TTP_XOR_QUAD_CurrentVersionRun_7d39 {
  strings:
    $key_7d39 = { 2e 56 [2] 0a 58 [2] 21 74 [2] 0f 56 [2] 1b 4d [2] 14 57 [2] 0a 4a [2] 08 4b [2] 13 4d [2] 0f 4a [2] 13 65 }

  condition:
    any of them
}