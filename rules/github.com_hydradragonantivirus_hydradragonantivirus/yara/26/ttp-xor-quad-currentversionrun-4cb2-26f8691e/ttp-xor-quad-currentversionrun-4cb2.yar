rule TTP_XOR_QUAD_CurrentVersionRun_4cb2 {
  strings:
    $key_4cb2 = { 1f dd [2] 3b d3 [2] 10 ff [2] 3e dd [2] 2a c6 [2] 25 dc [2] 3b c1 [2] 39 c0 [2] 22 c6 [2] 3e c1 [2] 22 ee }

  condition:
    any of them
}