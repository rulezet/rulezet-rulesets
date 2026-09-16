rule TTP_XOR_QUAD_CurrentVersionRun_40ae {
  strings:
    $key_40ae = { 13 c1 [2] 37 cf [2] 1c e3 [2] 32 c1 [2] 26 da [2] 29 c0 [2] 37 dd [2] 35 dc [2] 2e da [2] 32 dd [2] 2e f2 }

  condition:
    any of them
}