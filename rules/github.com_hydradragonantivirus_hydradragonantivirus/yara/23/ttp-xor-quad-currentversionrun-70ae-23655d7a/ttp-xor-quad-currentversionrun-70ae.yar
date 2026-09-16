rule TTP_XOR_QUAD_CurrentVersionRun_70ae {
  strings:
    $key_70ae = { 23 c1 [2] 07 cf [2] 2c e3 [2] 02 c1 [2] 16 da [2] 19 c0 [2] 07 dd [2] 05 dc [2] 1e da [2] 02 dd [2] 1e f2 }

  condition:
    any of them
}