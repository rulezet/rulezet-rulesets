rule TTP_XOR_QUAD_CurrentVersionRun_1db2 {
  strings:
    $key_1db2 = { 4e dd [2] 6a d3 [2] 41 ff [2] 6f dd [2] 7b c6 [2] 74 dc [2] 6a c1 [2] 68 c0 [2] 73 c6 [2] 6f c1 [2] 73 ee }

  condition:
    any of them
}