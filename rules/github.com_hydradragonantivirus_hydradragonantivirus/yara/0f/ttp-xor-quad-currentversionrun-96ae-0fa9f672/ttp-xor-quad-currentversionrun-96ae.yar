rule TTP_XOR_QUAD_CurrentVersionRun_96ae {
  strings:
    $key_96ae = { c5 c1 [2] e1 cf [2] ca e3 [2] e4 c1 [2] f0 da [2] ff c0 [2] e1 dd [2] e3 dc [2] f8 da [2] e4 dd [2] f8 f2 }

  condition:
    any of them
}