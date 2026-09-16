rule TTP_XOR_QUAD_CurrentVersionRun_c8bb {
  strings:
    $key_c8bb = { 9b d4 [2] bf da [2] 94 f6 [2] ba d4 [2] ae cf [2] a1 d5 [2] bf c8 [2] bd c9 [2] a6 cf [2] ba c8 [2] a6 e7 }

  condition:
    any of them
}