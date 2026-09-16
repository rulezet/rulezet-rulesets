rule TTP_XOR_QUAD_CurrentVersionRun_441a {
  strings:
    $key_441a = { 17 75 [2] 33 7b [2] 18 57 [2] 36 75 [2] 22 6e [2] 2d 74 [2] 33 69 [2] 31 68 [2] 2a 6e [2] 36 69 [2] 2a 46 }

  condition:
    any of them
}