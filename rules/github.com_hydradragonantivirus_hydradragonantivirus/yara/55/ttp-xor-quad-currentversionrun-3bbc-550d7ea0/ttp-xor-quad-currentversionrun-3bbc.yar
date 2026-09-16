rule TTP_XOR_QUAD_CurrentVersionRun_3bbc {
  strings:
    $key_3bbc = { 68 d3 [2] 4c dd [2] 67 f1 [2] 49 d3 [2] 5d c8 [2] 52 d2 [2] 4c cf [2] 4e ce [2] 55 c8 [2] 49 cf [2] 55 e0 }

  condition:
    any of them
}