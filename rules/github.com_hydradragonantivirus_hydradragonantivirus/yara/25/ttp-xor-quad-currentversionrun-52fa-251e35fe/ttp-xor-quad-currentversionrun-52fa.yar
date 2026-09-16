rule TTP_XOR_QUAD_CurrentVersionRun_52fa {
  strings:
    $key_52fa = { 01 95 [2] 25 9b [2] 0e b7 [2] 20 95 [2] 34 8e [2] 3b 94 [2] 25 89 [2] 27 88 [2] 3c 8e [2] 20 89 [2] 3c a6 }

  condition:
    any of them
}