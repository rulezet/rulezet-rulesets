rule TTP_XOR_QUAD_CurrentVersionRun_4cbd {
  strings:
    $key_4cbd = { 1f d2 [2] 3b dc [2] 10 f0 [2] 3e d2 [2] 2a c9 [2] 25 d3 [2] 3b ce [2] 39 cf [2] 22 c9 [2] 3e ce [2] 22 e1 }

  condition:
    any of them
}