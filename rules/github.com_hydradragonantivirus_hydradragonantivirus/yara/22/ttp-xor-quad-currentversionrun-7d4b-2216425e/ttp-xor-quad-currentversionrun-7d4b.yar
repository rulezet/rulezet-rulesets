rule TTP_XOR_QUAD_CurrentVersionRun_7d4b {
  strings:
    $key_7d4b = { 2e 24 [2] 0a 2a [2] 21 06 [2] 0f 24 [2] 1b 3f [2] 14 25 [2] 0a 38 [2] 08 39 [2] 13 3f [2] 0f 38 [2] 13 17 }

  condition:
    any of them
}