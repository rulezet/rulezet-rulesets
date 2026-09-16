rule TTP_XOR_QUAD_CurrentVersionRun_7d5a {
  strings:
    $key_7d5a = { 2e 35 [2] 0a 3b [2] 21 17 [2] 0f 35 [2] 1b 2e [2] 14 34 [2] 0a 29 [2] 08 28 [2] 13 2e [2] 0f 29 [2] 13 06 }

  condition:
    any of them
}