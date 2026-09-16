rule TTP_XOR_QUAD_CurrentVersionRun_fcb2 {
  strings:
    $key_fcb2 = { af dd [2] 8b d3 [2] a0 ff [2] 8e dd [2] 9a c6 [2] 95 dc [2] 8b c1 [2] 89 c0 [2] 92 c6 [2] 8e c1 [2] 92 ee }

  condition:
    any of them
}