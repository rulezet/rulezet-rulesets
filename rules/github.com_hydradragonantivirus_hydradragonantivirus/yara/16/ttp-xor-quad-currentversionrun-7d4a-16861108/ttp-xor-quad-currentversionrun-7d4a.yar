rule TTP_XOR_QUAD_CurrentVersionRun_7d4a {
  strings:
    $key_7d4a = { 2e 25 [2] 0a 2b [2] 21 07 [2] 0f 25 [2] 1b 3e [2] 14 24 [2] 0a 39 [2] 08 38 [2] 13 3e [2] 0f 39 [2] 13 16 }

  condition:
    any of them
}