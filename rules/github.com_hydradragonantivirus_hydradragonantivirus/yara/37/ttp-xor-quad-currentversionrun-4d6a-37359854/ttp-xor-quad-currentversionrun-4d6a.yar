rule TTP_XOR_QUAD_CurrentVersionRun_4d6a {
  strings:
    $key_4d6a = { 1e 05 [2] 3a 0b [2] 11 27 [2] 3f 05 [2] 2b 1e [2] 24 04 [2] 3a 19 [2] 38 18 [2] 23 1e [2] 3f 19 [2] 23 36 }

  condition:
    any of them
}