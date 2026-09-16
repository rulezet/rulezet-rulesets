rule TTP_XOR_QUAD_CurrentVersionRun_abae {
  strings:
    $key_abae = { f8 c1 [2] dc cf [2] f7 e3 [2] d9 c1 [2] cd da [2] c2 c0 [2] dc dd [2] de dc [2] c5 da [2] d9 dd [2] c5 f2 }

  condition:
    any of them
}