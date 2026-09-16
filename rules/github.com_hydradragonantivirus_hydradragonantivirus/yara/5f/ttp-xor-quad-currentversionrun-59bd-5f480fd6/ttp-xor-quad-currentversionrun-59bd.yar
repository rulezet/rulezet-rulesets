rule TTP_XOR_QUAD_CurrentVersionRun_59bd {
  strings:
    $key_59bd = { 0a d2 [2] 2e dc [2] 05 f0 [2] 2b d2 [2] 3f c9 [2] 30 d3 [2] 2e ce [2] 2c cf [2] 37 c9 [2] 2b ce [2] 37 e1 }

  condition:
    any of them
}