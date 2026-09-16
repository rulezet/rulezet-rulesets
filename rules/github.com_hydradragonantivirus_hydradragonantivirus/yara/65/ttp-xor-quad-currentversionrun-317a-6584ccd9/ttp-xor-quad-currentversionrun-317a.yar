rule TTP_XOR_QUAD_CurrentVersionRun_317a {
  strings:
    $key_317a = { 62 15 [2] 46 1b [2] 6d 37 [2] 43 15 [2] 57 0e [2] 58 14 [2] 46 09 [2] 44 08 [2] 5f 0e [2] 43 09 [2] 5f 26 }

  condition:
    any of them
}