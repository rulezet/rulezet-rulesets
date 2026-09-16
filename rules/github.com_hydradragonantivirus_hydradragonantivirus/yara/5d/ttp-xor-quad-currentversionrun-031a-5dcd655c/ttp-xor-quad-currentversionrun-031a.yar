rule TTP_XOR_QUAD_CurrentVersionRun_031a {
  strings:
    $key_031a = { 50 75 [2] 74 7b [2] 5f 57 [2] 71 75 [2] 65 6e [2] 6a 74 [2] 74 69 [2] 76 68 [2] 6d 6e [2] 71 69 [2] 6d 46 }

  condition:
    any of them
}