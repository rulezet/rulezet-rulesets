rule TTP_XOR_QUAD_CurrentVersionRun_02fa {
  strings:
    $key_02fa = { 51 95 [2] 75 9b [2] 5e b7 [2] 70 95 [2] 64 8e [2] 6b 94 [2] 75 89 [2] 77 88 [2] 6c 8e [2] 70 89 [2] 6c a6 }

  condition:
    any of them
}