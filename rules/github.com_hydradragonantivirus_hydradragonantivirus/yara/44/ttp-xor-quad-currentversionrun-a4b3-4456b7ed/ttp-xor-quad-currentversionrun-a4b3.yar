rule TTP_XOR_QUAD_CurrentVersionRun_a4b3 {
  strings:
    $key_a4b3 = { f7 dc [2] d3 d2 [2] f8 fe [2] d6 dc [2] c2 c7 [2] cd dd [2] d3 c0 [2] d1 c1 [2] ca c7 [2] d6 c0 [2] ca ef }

  condition:
    any of them
}