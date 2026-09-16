rule TTP_XOR_QUAD_CurrentVersionRun_77b2 {
  strings:
    $key_77b2 = { 24 dd [2] 00 d3 [2] 2b ff [2] 05 dd [2] 11 c6 [2] 1e dc [2] 00 c1 [2] 02 c0 [2] 19 c6 [2] 05 c1 [2] 19 ee }

  condition:
    any of them
}