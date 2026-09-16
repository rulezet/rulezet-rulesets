rule TTP_XOR_QUAD_CurrentVersionRun_1f1a {
  strings:
    $key_1f1a = { 4c 75 [2] 68 7b [2] 43 57 [2] 6d 75 [2] 79 6e [2] 76 74 [2] 68 69 [2] 6a 68 [2] 71 6e [2] 6d 69 [2] 71 46 }

  condition:
    any of them
}