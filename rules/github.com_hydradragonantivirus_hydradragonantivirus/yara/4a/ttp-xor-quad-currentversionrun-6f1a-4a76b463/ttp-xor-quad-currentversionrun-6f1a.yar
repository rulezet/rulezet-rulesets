rule TTP_XOR_QUAD_CurrentVersionRun_6f1a {
  strings:
    $key_6f1a = { 3c 75 [2] 18 7b [2] 33 57 [2] 1d 75 [2] 09 6e [2] 06 74 [2] 18 69 [2] 1a 68 [2] 01 6e [2] 1d 69 [2] 01 46 }

  condition:
    any of them
}