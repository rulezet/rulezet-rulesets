rule TTP_XOR_QUAD_CurrentVersionRun_27b2 {
  strings:
    $key_27b2 = { 74 dd [2] 50 d3 [2] 7b ff [2] 55 dd [2] 41 c6 [2] 4e dc [2] 50 c1 [2] 52 c0 [2] 49 c6 [2] 55 c1 [2] 49 ee }

  condition:
    any of them
}