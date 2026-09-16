rule TTP_XOR_QUAD_CurrentVersionRun_95ae {
  strings:
    $key_95ae = { c6 c1 [2] e2 cf [2] c9 e3 [2] e7 c1 [2] f3 da [2] fc c0 [2] e2 dd [2] e0 dc [2] fb da [2] e7 dd [2] fb f2 }

  condition:
    any of them
}