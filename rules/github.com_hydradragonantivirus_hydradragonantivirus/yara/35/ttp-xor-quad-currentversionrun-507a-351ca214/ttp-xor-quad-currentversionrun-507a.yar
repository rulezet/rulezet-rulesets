rule TTP_XOR_QUAD_CurrentVersionRun_507a {
  strings:
    $key_507a = { 03 15 [2] 27 1b [2] 0c 37 [2] 22 15 [2] 36 0e [2] 39 14 [2] 27 09 [2] 25 08 [2] 3e 0e [2] 22 09 [2] 3e 26 }

  condition:
    any of them
}