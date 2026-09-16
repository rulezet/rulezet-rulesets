rule TTP_XOR_QUAD_CurrentVersionRun_4d5a {
  strings:
    $key_4d5a = { 1e 35 [2] 3a 3b [2] 11 17 [2] 3f 35 [2] 2b 2e [2] 24 34 [2] 3a 29 [2] 38 28 [2] 23 2e [2] 3f 29 [2] 23 06 }

  condition:
    any of them
}