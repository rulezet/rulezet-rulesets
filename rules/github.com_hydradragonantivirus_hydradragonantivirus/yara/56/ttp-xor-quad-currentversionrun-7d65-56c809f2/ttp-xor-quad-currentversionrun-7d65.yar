rule TTP_XOR_QUAD_CurrentVersionRun_7d65 {
  strings:
    $key_7d65 = { 2e 0a [2] 0a 04 [2] 21 28 [2] 0f 0a [2] 1b 11 [2] 14 0b [2] 0a 16 [2] 08 17 [2] 13 11 [2] 0f 16 [2] 13 39 }

  condition:
    any of them
}