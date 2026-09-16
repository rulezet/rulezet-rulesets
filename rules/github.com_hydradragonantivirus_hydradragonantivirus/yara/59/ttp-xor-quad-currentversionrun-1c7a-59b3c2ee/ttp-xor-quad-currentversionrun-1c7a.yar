rule TTP_XOR_QUAD_CurrentVersionRun_1c7a {
  strings:
    $key_1c7a = { 4f 15 [2] 6b 1b [2] 40 37 [2] 6e 15 [2] 7a 0e [2] 75 14 [2] 6b 09 [2] 69 08 [2] 72 0e [2] 6e 09 [2] 72 26 }

  condition:
    any of them
}