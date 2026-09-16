rule TTP_XOR_QUAD_CurrentVersionRun_37fa {
  strings:
    $key_37fa = { 64 95 [2] 40 9b [2] 6b b7 [2] 45 95 [2] 51 8e [2] 5e 94 [2] 40 89 [2] 42 88 [2] 59 8e [2] 45 89 [2] 59 a6 }

  condition:
    any of them
}