rule TTP_XOR_QUAD_CurrentVersionRun_7c1a {
  strings:
    $key_7c1a = { 2f 75 [2] 0b 7b [2] 20 57 [2] 0e 75 [2] 1a 6e [2] 15 74 [2] 0b 69 [2] 09 68 [2] 12 6e [2] 0e 69 [2] 12 46 }

  condition:
    any of them
}