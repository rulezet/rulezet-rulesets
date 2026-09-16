rule TTP_XOR_QUAD_CurrentVersionRun_e4b2 {
  strings:
    $key_e4b2 = { b7 dd [2] 93 d3 [2] b8 ff [2] 96 dd [2] 82 c6 [2] 8d dc [2] 93 c1 [2] 91 c0 [2] 8a c6 [2] 96 c1 [2] 8a ee }

  condition:
    any of them
}