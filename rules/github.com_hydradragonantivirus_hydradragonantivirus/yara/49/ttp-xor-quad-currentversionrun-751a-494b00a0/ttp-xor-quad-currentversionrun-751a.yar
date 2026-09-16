rule TTP_XOR_QUAD_CurrentVersionRun_751a {
  strings:
    $key_751a = { 26 75 [2] 02 7b [2] 29 57 [2] 07 75 [2] 13 6e [2] 1c 74 [2] 02 69 [2] 00 68 [2] 1b 6e [2] 07 69 [2] 1b 46 }

  condition:
    any of them
}