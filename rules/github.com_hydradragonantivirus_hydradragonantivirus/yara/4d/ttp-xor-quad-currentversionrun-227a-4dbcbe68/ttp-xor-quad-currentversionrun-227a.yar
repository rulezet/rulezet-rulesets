rule TTP_XOR_QUAD_CurrentVersionRun_227a {
  strings:
    $key_227a = { 71 15 [2] 55 1b [2] 7e 37 [2] 50 15 [2] 44 0e [2] 4b 14 [2] 55 09 [2] 57 08 [2] 4c 0e [2] 50 09 [2] 4c 26 }

  condition:
    any of them
}