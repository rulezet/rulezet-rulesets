rule TTP_XOR_QUAD_CurrentVersionRun_86ae {
  strings:
    $key_86ae = { d5 c1 [2] f1 cf [2] da e3 [2] f4 c1 [2] e0 da [2] ef c0 [2] f1 dd [2] f3 dc [2] e8 da [2] f4 dd [2] e8 f2 }

  condition:
    any of them
}