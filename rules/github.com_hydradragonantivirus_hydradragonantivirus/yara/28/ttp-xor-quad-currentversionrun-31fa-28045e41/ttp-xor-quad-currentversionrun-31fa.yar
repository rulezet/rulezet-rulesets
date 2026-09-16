rule TTP_XOR_QUAD_CurrentVersionRun_31fa {
  strings:
    $key_31fa = { 62 95 [2] 46 9b [2] 6d b7 [2] 43 95 [2] 57 8e [2] 58 94 [2] 46 89 [2] 44 88 [2] 5f 8e [2] 43 89 [2] 5f a6 }

  condition:
    any of them
}