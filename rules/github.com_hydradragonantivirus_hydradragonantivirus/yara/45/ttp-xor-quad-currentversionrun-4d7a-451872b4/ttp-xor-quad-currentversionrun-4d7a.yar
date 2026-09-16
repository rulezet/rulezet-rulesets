rule TTP_XOR_QUAD_CurrentVersionRun_4d7a {
  strings:
    $key_4d7a = { 1e 15 [2] 3a 1b [2] 11 37 [2] 3f 15 [2] 2b 0e [2] 24 14 [2] 3a 09 [2] 38 08 [2] 23 0e [2] 3f 09 [2] 23 26 }

  condition:
    any of them
}