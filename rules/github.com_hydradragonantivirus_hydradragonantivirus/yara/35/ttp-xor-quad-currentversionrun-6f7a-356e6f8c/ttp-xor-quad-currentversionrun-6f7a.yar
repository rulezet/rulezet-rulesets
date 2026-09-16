rule TTP_XOR_QUAD_CurrentVersionRun_6f7a {
  strings:
    $key_6f7a = { 3c 15 [2] 18 1b [2] 33 37 [2] 1d 15 [2] 09 0e [2] 06 14 [2] 18 09 [2] 1a 08 [2] 01 0e [2] 1d 09 [2] 01 26 }

  condition:
    any of them
}