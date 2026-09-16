rule TTP_XOR_QUAD_CurrentVersionRun_91bc {
  strings:
    $key_91bc = { c2 d3 [2] e6 dd [2] cd f1 [2] e3 d3 [2] f7 c8 [2] f8 d2 [2] e6 cf [2] e4 ce [2] ff c8 [2] e3 cf [2] ff e0 }

  condition:
    any of them
}