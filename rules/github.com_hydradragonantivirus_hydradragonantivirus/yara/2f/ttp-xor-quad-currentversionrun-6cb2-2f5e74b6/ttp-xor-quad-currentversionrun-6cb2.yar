rule TTP_XOR_QUAD_CurrentVersionRun_6cb2 {
  strings:
    $key_6cb2 = { 3f dd [2] 1b d3 [2] 30 ff [2] 1e dd [2] 0a c6 [2] 05 dc [2] 1b c1 [2] 19 c0 [2] 02 c6 [2] 1e c1 [2] 02 ee }

  condition:
    any of them
}