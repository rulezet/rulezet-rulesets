rule TTP_XOR_QUAD_CurrentVersionRun_30b2 {
  strings:
    $key_30b2 = { 63 dd [2] 47 d3 [2] 6c ff [2] 42 dd [2] 56 c6 [2] 59 dc [2] 47 c1 [2] 45 c0 [2] 5e c6 [2] 42 c1 [2] 5e ee }

  condition:
    any of them
}