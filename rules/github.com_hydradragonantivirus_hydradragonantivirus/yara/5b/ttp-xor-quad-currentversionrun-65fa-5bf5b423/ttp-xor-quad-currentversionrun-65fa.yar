rule TTP_XOR_QUAD_CurrentVersionRun_65fa {
  strings:
    $key_65fa = { 36 95 [2] 12 9b [2] 39 b7 [2] 17 95 [2] 03 8e [2] 0c 94 [2] 12 89 [2] 10 88 [2] 0b 8e [2] 17 89 [2] 0b a6 }

  condition:
    any of them
}