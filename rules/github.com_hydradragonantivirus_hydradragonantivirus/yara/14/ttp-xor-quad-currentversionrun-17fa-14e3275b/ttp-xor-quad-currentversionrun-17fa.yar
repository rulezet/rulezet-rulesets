rule TTP_XOR_QUAD_CurrentVersionRun_17fa {
  strings:
    $key_17fa = { 44 95 [2] 60 9b [2] 4b b7 [2] 65 95 [2] 71 8e [2] 7e 94 [2] 60 89 [2] 62 88 [2] 79 8e [2] 65 89 [2] 79 a6 }

  condition:
    any of them
}