rule TTP_XOR_QUAD_CurrentVersionRun_04b2 {
  strings:
    $key_04b2 = { 57 dd [2] 73 d3 [2] 58 ff [2] 76 dd [2] 62 c6 [2] 6d dc [2] 73 c1 [2] 71 c0 [2] 6a c6 [2] 76 c1 [2] 6a ee }

  condition:
    any of them
}