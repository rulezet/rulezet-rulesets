rule TTP_XOR_QUAD_CurrentVersionRun_b1b2 {
  strings:
    $key_b1b2 = { e2 dd [2] c6 d3 [2] ed ff [2] c3 dd [2] d7 c6 [2] d8 dc [2] c6 c1 [2] c4 c0 [2] df c6 [2] c3 c1 [2] df ee }

  condition:
    any of them
}