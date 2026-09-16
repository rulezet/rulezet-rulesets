rule TTP_XOR_QUAD_CurrentVersionRun_7d24 {
  strings:
    $key_7d24 = { 2e 4b [2] 0a 45 [2] 21 69 [2] 0f 4b [2] 1b 50 [2] 14 4a [2] 0a 57 [2] 08 56 [2] 13 50 [2] 0f 57 [2] 13 78 }

  condition:
    any of them
}