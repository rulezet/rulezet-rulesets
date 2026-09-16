rule TTP_XOR_QUAD_CurrentVersionRun_5f7a {
  strings:
    $key_5f7a = { 0c 15 [2] 28 1b [2] 03 37 [2] 2d 15 [2] 39 0e [2] 36 14 [2] 28 09 [2] 2a 08 [2] 31 0e [2] 2d 09 [2] 31 26 }

  condition:
    any of them
}