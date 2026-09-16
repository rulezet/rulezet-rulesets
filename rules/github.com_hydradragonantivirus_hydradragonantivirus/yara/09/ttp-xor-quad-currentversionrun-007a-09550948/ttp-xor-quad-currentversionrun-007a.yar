rule TTP_XOR_QUAD_CurrentVersionRun_007a {
  strings:
    $key_007a = { 53 15 [2] 77 1b [2] 5c 37 [2] 72 15 [2] 66 0e [2] 69 14 [2] 77 09 [2] 75 08 [2] 6e 0e [2] 72 09 [2] 6e 26 }

  condition:
    any of them
}