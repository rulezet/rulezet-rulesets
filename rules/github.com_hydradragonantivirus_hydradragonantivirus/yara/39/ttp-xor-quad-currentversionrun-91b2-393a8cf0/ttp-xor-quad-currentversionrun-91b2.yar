rule TTP_XOR_QUAD_CurrentVersionRun_91b2 {
  strings:
    $key_91b2 = { c2 dd [2] e6 d3 [2] cd ff [2] e3 dd [2] f7 c6 [2] f8 dc [2] e6 c1 [2] e4 c0 [2] ff c6 [2] e3 c1 [2] ff ee }

  condition:
    any of them
}