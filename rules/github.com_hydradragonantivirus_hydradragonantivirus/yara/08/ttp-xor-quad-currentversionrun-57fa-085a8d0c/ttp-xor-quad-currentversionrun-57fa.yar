rule TTP_XOR_QUAD_CurrentVersionRun_57fa {
  strings:
    $key_57fa = { 04 95 [2] 20 9b [2] 0b b7 [2] 25 95 [2] 31 8e [2] 3e 94 [2] 20 89 [2] 22 88 [2] 39 8e [2] 25 89 [2] 39 a6 }

  condition:
    any of them
}