rule TTP_XOR_QUAD_CurrentVersionRun_53ae {
  strings:
    $key_53ae = { 00 c1 [2] 24 cf [2] 0f e3 [2] 21 c1 [2] 35 da [2] 3a c0 [2] 24 dd [2] 26 dc [2] 3d da [2] 21 dd [2] 3d f2 }

  condition:
    any of them
}