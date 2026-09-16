rule TTP_XOR_QUAD_CurrentVersionRun_2f7a {
  strings:
    $key_2f7a = { 7c 15 [2] 58 1b [2] 73 37 [2] 5d 15 [2] 49 0e [2] 46 14 [2] 58 09 [2] 5a 08 [2] 41 0e [2] 5d 09 [2] 41 26 }

  condition:
    any of them
}