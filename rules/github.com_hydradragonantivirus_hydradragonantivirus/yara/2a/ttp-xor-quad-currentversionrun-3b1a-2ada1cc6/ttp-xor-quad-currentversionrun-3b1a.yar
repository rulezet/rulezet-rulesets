rule TTP_XOR_QUAD_CurrentVersionRun_3b1a {
  strings:
    $key_3b1a = { 68 75 [2] 4c 7b [2] 67 57 [2] 49 75 [2] 5d 6e [2] 52 74 [2] 4c 69 [2] 4e 68 [2] 55 6e [2] 49 69 [2] 55 46 }

  condition:
    any of them
}