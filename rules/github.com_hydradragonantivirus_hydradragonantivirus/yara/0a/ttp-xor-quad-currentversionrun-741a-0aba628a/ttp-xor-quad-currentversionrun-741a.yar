rule TTP_XOR_QUAD_CurrentVersionRun_741a {
  strings:
    $key_741a = { 27 75 [2] 03 7b [2] 28 57 [2] 06 75 [2] 12 6e [2] 1d 74 [2] 03 69 [2] 01 68 [2] 1a 6e [2] 06 69 [2] 1a 46 }

  condition:
    any of them
}