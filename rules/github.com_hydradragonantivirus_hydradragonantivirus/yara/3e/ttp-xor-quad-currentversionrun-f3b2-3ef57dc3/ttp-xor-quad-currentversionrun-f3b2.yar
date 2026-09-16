rule TTP_XOR_QUAD_CurrentVersionRun_f3b2 {
  strings:
    $key_f3b2 = { a0 dd [2] 84 d3 [2] af ff [2] 81 dd [2] 95 c6 [2] 9a dc [2] 84 c1 [2] 86 c0 [2] 9d c6 [2] 81 c1 [2] 9d ee }

  condition:
    any of them
}