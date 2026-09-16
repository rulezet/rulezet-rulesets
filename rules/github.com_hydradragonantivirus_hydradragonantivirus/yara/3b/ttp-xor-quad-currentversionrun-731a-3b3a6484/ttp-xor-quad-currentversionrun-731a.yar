rule TTP_XOR_QUAD_CurrentVersionRun_731a {
  strings:
    $key_731a = { 20 75 [2] 04 7b [2] 2f 57 [2] 01 75 [2] 15 6e [2] 1a 74 [2] 04 69 [2] 06 68 [2] 1d 6e [2] 01 69 [2] 1d 46 }

  condition:
    any of them
}