rule TTP_XOR_QUAD_CurrentVersionRun_f9b2 {
  strings:
    $key_f9b2 = { aa dd [2] 8e d3 [2] a5 ff [2] 8b dd [2] 9f c6 [2] 90 dc [2] 8e c1 [2] 8c c0 [2] 97 c6 [2] 8b c1 [2] 97 ee }

  condition:
    any of them
}