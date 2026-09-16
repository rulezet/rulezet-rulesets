rule TTP_XOR_QUAD_CurrentVersionRun_c8bc {
  strings:
    $key_c8bc = { 9b d3 [2] bf dd [2] 94 f1 [2] ba d3 [2] ae c8 [2] a1 d2 [2] bf cf [2] bd ce [2] a6 c8 [2] ba cf [2] a6 e0 }

  condition:
    any of them
}