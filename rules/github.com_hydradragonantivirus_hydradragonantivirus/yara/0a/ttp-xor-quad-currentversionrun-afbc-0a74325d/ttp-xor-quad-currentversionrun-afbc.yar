rule TTP_XOR_QUAD_CurrentVersionRun_afbc {
  strings:
    $key_afbc = { fc d3 [2] d8 dd [2] f3 f1 [2] dd d3 [2] c9 c8 [2] c6 d2 [2] d8 cf [2] da ce [2] c1 c8 [2] dd cf [2] c1 e0 }

  condition:
    any of them
}