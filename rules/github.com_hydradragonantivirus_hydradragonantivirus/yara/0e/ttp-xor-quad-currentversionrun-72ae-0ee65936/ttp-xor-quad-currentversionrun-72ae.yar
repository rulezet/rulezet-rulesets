rule TTP_XOR_QUAD_CurrentVersionRun_72ae {
  strings:
    $key_72ae = { 21 c1 [2] 05 cf [2] 2e e3 [2] 00 c1 [2] 14 da [2] 1b c0 [2] 05 dd [2] 07 dc [2] 1c da [2] 00 dd [2] 1c f2 }

  condition:
    any of them
}