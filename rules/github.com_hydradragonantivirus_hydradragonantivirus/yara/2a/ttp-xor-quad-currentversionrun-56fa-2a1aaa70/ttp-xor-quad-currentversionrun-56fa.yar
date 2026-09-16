rule TTP_XOR_QUAD_CurrentVersionRun_56fa {
  strings:
    $key_56fa = { 05 95 [2] 21 9b [2] 0a b7 [2] 24 95 [2] 30 8e [2] 3f 94 [2] 21 89 [2] 23 88 [2] 38 8e [2] 24 89 [2] 38 a6 }

  condition:
    any of them
}