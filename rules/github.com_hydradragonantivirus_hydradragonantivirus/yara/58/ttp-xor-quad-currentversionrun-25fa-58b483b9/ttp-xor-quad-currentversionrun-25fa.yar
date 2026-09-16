rule TTP_XOR_QUAD_CurrentVersionRun_25fa {
  strings:
    $key_25fa = { 76 95 [2] 52 9b [2] 79 b7 [2] 57 95 [2] 43 8e [2] 4c 94 [2] 52 89 [2] 50 88 [2] 4b 8e [2] 57 89 [2] 4b a6 }

  condition:
    any of them
}