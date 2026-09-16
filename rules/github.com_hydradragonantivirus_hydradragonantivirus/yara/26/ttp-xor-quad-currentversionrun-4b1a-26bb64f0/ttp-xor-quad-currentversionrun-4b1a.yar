rule TTP_XOR_QUAD_CurrentVersionRun_4b1a {
  strings:
    $key_4b1a = { 18 75 [2] 3c 7b [2] 17 57 [2] 39 75 [2] 2d 6e [2] 22 74 [2] 3c 69 [2] 3e 68 [2] 25 6e [2] 39 69 [2] 25 46 }

  condition:
    any of them
}