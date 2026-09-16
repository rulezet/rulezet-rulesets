rule TTP_XOR_QUAD_CurrentVersionRun_3e7a {
  strings:
    $key_3e7a = { 6d 15 [2] 49 1b [2] 62 37 [2] 4c 15 [2] 58 0e [2] 57 14 [2] 49 09 [2] 4b 08 [2] 50 0e [2] 4c 09 [2] 50 26 }

  condition:
    any of them
}