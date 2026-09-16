rule TTP_XOR_QUAD_CurrentVersionRun_bbea {
  strings:
    $key_bbea = { e8 85 [2] cc 8b [2] e7 a7 [2] c9 85 [2] dd 9e [2] d2 84 [2] cc 99 [2] ce 98 [2] d5 9e [2] c9 99 [2] d5 b6 }

  condition:
    any of them
}