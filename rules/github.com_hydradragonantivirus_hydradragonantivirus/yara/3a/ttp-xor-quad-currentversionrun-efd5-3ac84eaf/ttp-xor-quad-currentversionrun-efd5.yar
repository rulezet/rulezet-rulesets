rule TTP_XOR_QUAD_CurrentVersionRun_efd5 {
  strings:
    $key_efd5 = { bc ba [2] 98 b4 [2] b3 98 [2] 9d ba [2] 89 a1 [2] 86 bb [2] 98 a6 [2] 9a a7 [2] 81 a1 [2] 9d a6 [2] 81 89 }

  condition:
    any of them
}