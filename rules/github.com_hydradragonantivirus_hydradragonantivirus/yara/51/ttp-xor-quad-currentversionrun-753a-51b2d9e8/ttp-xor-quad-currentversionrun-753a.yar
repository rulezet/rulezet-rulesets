rule TTP_XOR_QUAD_CurrentVersionRun_753a {
  strings:
    $key_753a = { 26 55 [2] 02 5b [2] 29 77 [2] 07 55 [2] 13 4e [2] 1c 54 [2] 02 49 [2] 00 48 [2] 1b 4e [2] 07 49 [2] 1b 66 }

  condition:
    any of them
}