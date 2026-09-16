rule TTP_XOR_QUAD_CurrentVersionRun_647a {
  strings:
    $key_647a = { 37 15 [2] 13 1b [2] 38 37 [2] 16 15 [2] 02 0e [2] 0d 14 [2] 13 09 [2] 11 08 [2] 0a 0e [2] 16 09 [2] 0a 26 }

  condition:
    any of them
}