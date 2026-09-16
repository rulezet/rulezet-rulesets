rule TTP_XOR_QUAD_CurrentVersionRun_22fa {
  strings:
    $key_22fa = { 71 95 [2] 55 9b [2] 7e b7 [2] 50 95 [2] 44 8e [2] 4b 94 [2] 55 89 [2] 57 88 [2] 4c 8e [2] 50 89 [2] 4c a6 }

  condition:
    any of them
}