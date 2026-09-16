rule TTP_XOR_QUAD_CurrentVersionRun_ebbc {
  strings:
    $key_ebbc = { b8 d3 [2] 9c dd [2] b7 f1 [2] 99 d3 [2] 8d c8 [2] 82 d2 [2] 9c cf [2] 9e ce [2] 85 c8 [2] 99 cf [2] 85 e0 }

  condition:
    any of them
}