rule TTP_XOR_QUAD_CurrentVersionRun_3db2 {
  strings:
    $key_3db2 = { 6e dd [2] 4a d3 [2] 61 ff [2] 4f dd [2] 5b c6 [2] 54 dc [2] 4a c1 [2] 48 c0 [2] 53 c6 [2] 4f c1 [2] 53 ee }

  condition:
    any of them
}