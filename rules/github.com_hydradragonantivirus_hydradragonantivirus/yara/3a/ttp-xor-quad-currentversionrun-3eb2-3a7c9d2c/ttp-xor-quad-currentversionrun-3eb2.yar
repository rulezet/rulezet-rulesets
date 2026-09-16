rule TTP_XOR_QUAD_CurrentVersionRun_3eb2 {
  strings:
    $key_3eb2 = { 6d dd [2] 49 d3 [2] 62 ff [2] 4c dd [2] 58 c6 [2] 57 dc [2] 49 c1 [2] 4b c0 [2] 50 c6 [2] 4c c1 [2] 50 ee }

  condition:
    any of them
}