rule TTP_XOR_QUAD_CurrentVersionRun_7e7a {
  strings:
    $key_7e7a = { 2d 15 [2] 09 1b [2] 22 37 [2] 0c 15 [2] 18 0e [2] 17 14 [2] 09 09 [2] 0b 08 [2] 10 0e [2] 0c 09 [2] 10 26 }

  condition:
    any of them
}