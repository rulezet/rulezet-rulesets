rule TTP_XOR_QUAD_CurrentVersionRun_651a {
  strings:
    $key_651a = { 36 75 [2] 12 7b [2] 39 57 [2] 17 75 [2] 03 6e [2] 0c 74 [2] 12 69 [2] 10 68 [2] 0b 6e [2] 17 69 [2] 0b 46 }

  condition:
    any of them
}