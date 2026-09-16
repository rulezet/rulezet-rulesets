rule TTP_XOR_QUAD_CurrentVersionRun_7d17 {
  strings:
    $key_7d17 = { 2e 78 [2] 0a 76 [2] 21 5a [2] 0f 78 [2] 1b 63 [2] 14 79 [2] 0a 64 [2] 08 65 [2] 13 63 [2] 0f 64 [2] 13 4b }

  condition:
    any of them
}