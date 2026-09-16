rule TTP_XOR_QUAD_CurrentVersionRun_92ae {
  strings:
    $key_92ae = { c1 c1 [2] e5 cf [2] ce e3 [2] e0 c1 [2] f4 da [2] fb c0 [2] e5 dd [2] e7 dc [2] fc da [2] e0 dd [2] fc f2 }

  condition:
    any of them
}