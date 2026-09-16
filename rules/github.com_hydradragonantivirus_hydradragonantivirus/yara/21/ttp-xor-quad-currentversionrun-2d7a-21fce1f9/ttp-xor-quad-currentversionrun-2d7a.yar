rule TTP_XOR_QUAD_CurrentVersionRun_2d7a {
  strings:
    $key_2d7a = { 7e 15 [2] 5a 1b [2] 71 37 [2] 5f 15 [2] 4b 0e [2] 44 14 [2] 5a 09 [2] 58 08 [2] 43 0e [2] 5f 09 [2] 43 26 }

  condition:
    any of them
}