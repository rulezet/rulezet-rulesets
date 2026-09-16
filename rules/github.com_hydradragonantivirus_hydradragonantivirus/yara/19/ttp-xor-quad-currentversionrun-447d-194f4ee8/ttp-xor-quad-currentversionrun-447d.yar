rule TTP_XOR_QUAD_CurrentVersionRun_447d {
  strings:
    $key_447d = { 17 12 [2] 33 1c [2] 18 30 [2] 36 12 [2] 22 09 [2] 2d 13 [2] 33 0e [2] 31 0f [2] 2a 09 [2] 36 0e [2] 2a 21 }

  condition:
    any of them
}