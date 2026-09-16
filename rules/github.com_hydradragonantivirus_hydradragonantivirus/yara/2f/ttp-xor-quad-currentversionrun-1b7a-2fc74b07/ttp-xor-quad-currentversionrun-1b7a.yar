rule TTP_XOR_QUAD_CurrentVersionRun_1b7a {
  strings:
    $key_1b7a = { 48 15 [2] 6c 1b [2] 47 37 [2] 69 15 [2] 7d 0e [2] 72 14 [2] 6c 09 [2] 6e 08 [2] 75 0e [2] 69 09 [2] 75 26 }

  condition:
    any of them
}