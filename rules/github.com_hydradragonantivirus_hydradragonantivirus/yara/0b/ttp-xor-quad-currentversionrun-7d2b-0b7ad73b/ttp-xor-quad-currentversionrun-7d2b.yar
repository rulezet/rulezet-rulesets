rule TTP_XOR_QUAD_CurrentVersionRun_7d2b {
  strings:
    $key_7d2b = { 2e 44 [2] 0a 4a [2] 21 66 [2] 0f 44 [2] 1b 5f [2] 14 45 [2] 0a 58 [2] 08 59 [2] 13 5f [2] 0f 58 [2] 13 77 }

  condition:
    any of them
}