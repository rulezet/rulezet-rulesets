rule TTP_XOR_QUAD_CurrentVersionRun_34b2 {
  strings:
    $key_34b2 = { 67 dd [2] 43 d3 [2] 68 ff [2] 46 dd [2] 52 c6 [2] 5d dc [2] 43 c1 [2] 41 c0 [2] 5a c6 [2] 46 c1 [2] 5a ee }

  condition:
    any of them
}