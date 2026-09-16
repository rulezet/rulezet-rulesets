rule TTP_XOR_QUAD_CurrentVersionRun_1a7a {
  strings:
    $key_1a7a = { 49 15 [2] 6d 1b [2] 46 37 [2] 68 15 [2] 7c 0e [2] 73 14 [2] 6d 09 [2] 6f 08 [2] 74 0e [2] 68 09 [2] 74 26 }

  condition:
    any of them
}