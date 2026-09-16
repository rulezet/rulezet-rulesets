rule TTP_XOR_QUAD_CurrentVersionRun_14b2 {
  strings:
    $key_14b2 = { 47 dd [2] 63 d3 [2] 48 ff [2] 66 dd [2] 72 c6 [2] 7d dc [2] 63 c1 [2] 61 c0 [2] 7a c6 [2] 66 c1 [2] 7a ee }

  condition:
    any of them
}