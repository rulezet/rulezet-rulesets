rule TTP_XOR_QUAD_CurrentVersionRun_93ae {
  strings:
    $key_93ae = { c0 c1 [2] e4 cf [2] cf e3 [2] e1 c1 [2] f5 da [2] fa c0 [2] e4 dd [2] e6 dc [2] fd da [2] e1 dd [2] fd f2 }

  condition:
    any of them
}