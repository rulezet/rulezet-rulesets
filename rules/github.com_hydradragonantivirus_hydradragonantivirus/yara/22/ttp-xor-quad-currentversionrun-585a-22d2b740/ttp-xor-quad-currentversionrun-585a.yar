rule TTP_XOR_QUAD_CurrentVersionRun_585a {
  strings:
    $key_585a = { 0b 35 [2] 2f 3b [2] 04 17 [2] 2a 35 [2] 3e 2e [2] 31 34 [2] 2f 29 [2] 2d 28 [2] 36 2e [2] 2a 29 [2] 36 06 }

  condition:
    any of them
}