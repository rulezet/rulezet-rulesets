rule TTP_XOR_QUAD_CurrentVersionRun_481a {
  strings:
    $key_481a = { 1b 75 [2] 3f 7b [2] 14 57 [2] 3a 75 [2] 2e 6e [2] 21 74 [2] 3f 69 [2] 3d 68 [2] 26 6e [2] 3a 69 [2] 26 46 }

  condition:
    any of them
}