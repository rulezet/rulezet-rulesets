rule TTP_XOR_QUAD_CurrentVersionRun_54b2 {
  strings:
    $key_54b2 = { 07 dd [2] 23 d3 [2] 08 ff [2] 26 dd [2] 32 c6 [2] 3d dc [2] 23 c1 [2] 21 c0 [2] 3a c6 [2] 26 c1 [2] 3a ee }

  condition:
    any of them
}