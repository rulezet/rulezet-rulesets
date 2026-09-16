rule TTP_XOR_QUAD_CurrentVersionRun_55fa {
  strings:
    $key_55fa = { 06 95 [2] 22 9b [2] 09 b7 [2] 27 95 [2] 33 8e [2] 3c 94 [2] 22 89 [2] 20 88 [2] 3b 8e [2] 27 89 [2] 3b a6 }

  condition:
    any of them
}