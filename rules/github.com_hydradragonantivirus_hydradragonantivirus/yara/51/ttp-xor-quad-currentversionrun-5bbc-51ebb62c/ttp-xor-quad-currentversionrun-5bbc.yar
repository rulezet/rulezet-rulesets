rule TTP_XOR_QUAD_CurrentVersionRun_5bbc {
  strings:
    $key_5bbc = { 08 d3 [2] 2c dd [2] 07 f1 [2] 29 d3 [2] 3d c8 [2] 32 d2 [2] 2c cf [2] 2e ce [2] 35 c8 [2] 29 cf [2] 35 e0 }

  condition:
    any of them
}