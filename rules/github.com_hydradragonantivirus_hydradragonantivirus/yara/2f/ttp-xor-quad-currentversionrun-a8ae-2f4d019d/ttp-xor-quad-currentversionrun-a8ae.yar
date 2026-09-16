rule TTP_XOR_QUAD_CurrentVersionRun_a8ae {
  strings:
    $key_a8ae = { fb c1 [2] df cf [2] f4 e3 [2] da c1 [2] ce da [2] c1 c0 [2] df dd [2] dd dc [2] c6 da [2] da dd [2] c6 f2 }

  condition:
    any of them
}