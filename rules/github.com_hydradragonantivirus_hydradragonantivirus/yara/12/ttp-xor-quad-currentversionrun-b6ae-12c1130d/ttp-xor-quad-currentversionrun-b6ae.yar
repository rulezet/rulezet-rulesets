rule TTP_XOR_QUAD_CurrentVersionRun_b6ae {
  strings:
    $key_b6ae = { e5 c1 [2] c1 cf [2] ea e3 [2] c4 c1 [2] d0 da [2] df c0 [2] c1 dd [2] c3 dc [2] d8 da [2] c4 dd [2] d8 f2 }

  condition:
    any of them
}