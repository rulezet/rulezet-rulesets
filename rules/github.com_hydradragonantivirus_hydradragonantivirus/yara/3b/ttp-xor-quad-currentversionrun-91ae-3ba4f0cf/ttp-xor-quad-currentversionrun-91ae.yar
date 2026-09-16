rule TTP_XOR_QUAD_CurrentVersionRun_91ae {
  strings:
    $key_91ae = { c2 c1 [2] e6 cf [2] cd e3 [2] e3 c1 [2] f7 da [2] f8 c0 [2] e6 dd [2] e4 dc [2] ff da [2] e3 dd [2] ff f2 }

  condition:
    any of them
}