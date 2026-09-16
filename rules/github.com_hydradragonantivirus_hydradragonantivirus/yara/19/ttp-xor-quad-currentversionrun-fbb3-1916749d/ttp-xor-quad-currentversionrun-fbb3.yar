rule TTP_XOR_QUAD_CurrentVersionRun_fbb3 {
  strings:
    $key_fbb3 = { a8 dc [2] 8c d2 [2] a7 fe [2] 89 dc [2] 9d c7 [2] 92 dd [2] 8c c0 [2] 8e c1 [2] 95 c7 [2] 89 c0 [2] 95 ef }

  condition:
    any of them
}