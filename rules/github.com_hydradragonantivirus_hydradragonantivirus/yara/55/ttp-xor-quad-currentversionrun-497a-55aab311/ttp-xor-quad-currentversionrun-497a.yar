rule TTP_XOR_QUAD_CurrentVersionRun_497a {
  strings:
    $key_497a = { 1a 15 [2] 3e 1b [2] 15 37 [2] 3b 15 [2] 2f 0e [2] 20 14 [2] 3e 09 [2] 3c 08 [2] 27 0e [2] 3b 09 [2] 27 26 }

  condition:
    any of them
}