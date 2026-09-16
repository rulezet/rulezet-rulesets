rule TTP_XOR_QUAD_CurrentVersionRun_67b2 {
  strings:
    $key_67b2 = { 34 dd [2] 10 d3 [2] 3b ff [2] 15 dd [2] 01 c6 [2] 0e dc [2] 10 c1 [2] 12 c0 [2] 09 c6 [2] 15 c1 [2] 09 ee }

  condition:
    any of them
}