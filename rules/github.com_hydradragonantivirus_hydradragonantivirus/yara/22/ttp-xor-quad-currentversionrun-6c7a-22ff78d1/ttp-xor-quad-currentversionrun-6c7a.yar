rule TTP_XOR_QUAD_CurrentVersionRun_6c7a {
  strings:
    $key_6c7a = { 3f 15 [2] 1b 1b [2] 30 37 [2] 1e 15 [2] 0a 0e [2] 05 14 [2] 1b 09 [2] 19 08 [2] 02 0e [2] 1e 09 [2] 02 26 }

  condition:
    any of them
}