rule TTP_XOR_QUAD_CurrentVersionRun_0fb2 {
  strings:
    $key_0fb2 = { 5c dd [2] 78 d3 [2] 53 ff [2] 7d dd [2] 69 c6 [2] 66 dc [2] 78 c1 [2] 7a c0 [2] 61 c6 [2] 7d c1 [2] 61 ee }

  condition:
    any of them
}