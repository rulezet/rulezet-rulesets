rule TTP_XOR_QUAD_CurrentVersionRun_4bbc {
  strings:
    $key_4bbc = { 18 d3 [2] 3c dd [2] 17 f1 [2] 39 d3 [2] 2d c8 [2] 22 d2 [2] 3c cf [2] 3e ce [2] 25 c8 [2] 39 cf [2] 25 e0 }

  condition:
    any of them
}