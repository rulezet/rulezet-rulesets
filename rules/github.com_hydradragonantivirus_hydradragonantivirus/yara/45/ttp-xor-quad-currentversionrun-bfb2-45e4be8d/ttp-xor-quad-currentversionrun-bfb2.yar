rule TTP_XOR_QUAD_CurrentVersionRun_bfb2 {
  strings:
    $key_bfb2 = { ec dd [2] c8 d3 [2] e3 ff [2] cd dd [2] d9 c6 [2] d6 dc [2] c8 c1 [2] ca c0 [2] d1 c6 [2] cd c1 [2] d1 ee }

  condition:
    any of them
}