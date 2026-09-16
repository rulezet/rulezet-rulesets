rule TTP_XOR_QUAD_CurrentVersionRun_7c5a {
  strings:
    $key_7c5a = { 2f 35 [2] 0b 3b [2] 20 17 [2] 0e 35 [2] 1a 2e [2] 15 34 [2] 0b 29 [2] 09 28 [2] 12 2e [2] 0e 29 [2] 12 06 }

  condition:
    any of them
}