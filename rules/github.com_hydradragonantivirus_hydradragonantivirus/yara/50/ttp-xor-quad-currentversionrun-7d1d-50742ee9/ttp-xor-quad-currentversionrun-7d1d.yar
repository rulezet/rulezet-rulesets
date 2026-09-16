rule TTP_XOR_QUAD_CurrentVersionRun_7d1d {
  strings:
    $key_7d1d = { 2e 72 [2] 0a 7c [2] 21 50 [2] 0f 72 [2] 1b 69 [2] 14 73 [2] 0a 6e [2] 08 6f [2] 13 69 [2] 0f 6e [2] 13 41 }

  condition:
    any of them
}