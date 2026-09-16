rule TTP_XOR_QUAD_CurrentVersionRun_4c7a {
  strings:
    $key_4c7a = { 1f 15 [2] 3b 1b [2] 10 37 [2] 3e 15 [2] 2a 0e [2] 25 14 [2] 3b 09 [2] 39 08 [2] 22 0e [2] 3e 09 [2] 22 26 }

  condition:
    any of them
}