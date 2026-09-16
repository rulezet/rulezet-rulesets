rule TTP_XOR_QUAD_CurrentVersionRun_757a {
  strings:
    $key_757a = { 26 15 [2] 02 1b [2] 29 37 [2] 07 15 [2] 13 0e [2] 1c 14 [2] 02 09 [2] 00 08 [2] 1b 0e [2] 07 09 [2] 1b 26 }

  condition:
    any of them
}