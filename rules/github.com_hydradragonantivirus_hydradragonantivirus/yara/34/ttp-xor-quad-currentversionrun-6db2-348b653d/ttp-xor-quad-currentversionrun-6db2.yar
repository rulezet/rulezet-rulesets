rule TTP_XOR_QUAD_CurrentVersionRun_6db2 {
  strings:
    $key_6db2 = { 3e dd [2] 1a d3 [2] 31 ff [2] 1f dd [2] 0b c6 [2] 04 dc [2] 1a c1 [2] 18 c0 [2] 03 c6 [2] 1f c1 [2] 03 ee }

  condition:
    any of them
}