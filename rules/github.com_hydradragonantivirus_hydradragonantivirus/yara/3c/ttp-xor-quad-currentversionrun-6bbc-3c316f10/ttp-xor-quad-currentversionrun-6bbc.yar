rule TTP_XOR_QUAD_CurrentVersionRun_6bbc {
  strings:
    $key_6bbc = { 38 d3 [2] 1c dd [2] 37 f1 [2] 19 d3 [2] 0d c8 [2] 02 d2 [2] 1c cf [2] 1e ce [2] 05 c8 [2] 19 cf [2] 05 e0 }

  condition:
    any of them
}