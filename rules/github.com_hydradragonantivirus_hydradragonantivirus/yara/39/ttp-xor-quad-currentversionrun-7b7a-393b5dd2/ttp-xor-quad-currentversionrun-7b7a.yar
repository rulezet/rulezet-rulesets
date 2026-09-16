rule TTP_XOR_QUAD_CurrentVersionRun_7b7a {
  strings:
    $key_7b7a = { 28 15 [2] 0c 1b [2] 27 37 [2] 09 15 [2] 1d 0e [2] 12 14 [2] 0c 09 [2] 0e 08 [2] 15 0e [2] 09 09 [2] 15 26 }

  condition:
    any of them
}