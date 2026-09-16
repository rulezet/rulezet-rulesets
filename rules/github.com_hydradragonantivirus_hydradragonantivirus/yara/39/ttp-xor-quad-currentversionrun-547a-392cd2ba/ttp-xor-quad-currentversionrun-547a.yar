rule TTP_XOR_QUAD_CurrentVersionRun_547a {
  strings:
    $key_547a = { 07 15 [2] 23 1b [2] 08 37 [2] 26 15 [2] 32 0e [2] 3d 14 [2] 23 09 [2] 21 08 [2] 3a 0e [2] 26 09 [2] 3a 26 }

  condition:
    any of them
}