rule TTP_XOR_QUAD_CurrentVersionRun_4d7d {
  strings:
    $key_4d7d = { 1e 12 [2] 3a 1c [2] 11 30 [2] 3f 12 [2] 2b 09 [2] 24 13 [2] 3a 0e [2] 38 0f [2] 23 09 [2] 3f 0e [2] 23 21 }

  condition:
    any of them
}