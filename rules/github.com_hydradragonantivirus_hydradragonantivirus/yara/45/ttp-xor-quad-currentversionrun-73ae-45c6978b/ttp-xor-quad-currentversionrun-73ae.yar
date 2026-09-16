rule TTP_XOR_QUAD_CurrentVersionRun_73ae {
  strings:
    $key_73ae = { 20 c1 [2] 04 cf [2] 2f e3 [2] 01 c1 [2] 15 da [2] 1a c0 [2] 04 dd [2] 06 dc [2] 1d da [2] 01 dd [2] 1d f2 }

  condition:
    any of them
}