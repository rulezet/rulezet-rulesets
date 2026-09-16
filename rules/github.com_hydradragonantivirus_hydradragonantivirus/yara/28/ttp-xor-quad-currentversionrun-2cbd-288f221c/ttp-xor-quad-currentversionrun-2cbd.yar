rule TTP_XOR_QUAD_CurrentVersionRun_2cbd {
  strings:
    $key_2cbd = { 7f d2 [2] 5b dc [2] 70 f0 [2] 5e d2 [2] 4a c9 [2] 45 d3 [2] 5b ce [2] 59 cf [2] 42 c9 [2] 5e ce [2] 42 e1 }

  condition:
    any of them
}