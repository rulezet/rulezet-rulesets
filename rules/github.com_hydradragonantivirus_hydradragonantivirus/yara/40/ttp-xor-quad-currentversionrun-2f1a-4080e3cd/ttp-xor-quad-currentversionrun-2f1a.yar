rule TTP_XOR_QUAD_CurrentVersionRun_2f1a {
  strings:
    $key_2f1a = { 7c 75 [2] 58 7b [2] 73 57 [2] 5d 75 [2] 49 6e [2] 46 74 [2] 58 69 [2] 5a 68 [2] 41 6e [2] 5d 69 [2] 41 46 }

  condition:
    any of them
}