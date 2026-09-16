rule TTP_XOR_QUAD_CurrentVersionRun_7f7a {
  strings:
    $key_7f7a = { 2c 15 [2] 08 1b [2] 23 37 [2] 0d 15 [2] 19 0e [2] 16 14 [2] 08 09 [2] 0a 08 [2] 11 0e [2] 0d 09 [2] 11 26 }

  condition:
    any of them
}