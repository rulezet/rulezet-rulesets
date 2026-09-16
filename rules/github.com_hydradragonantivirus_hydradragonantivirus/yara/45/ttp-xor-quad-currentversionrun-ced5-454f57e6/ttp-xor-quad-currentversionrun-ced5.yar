rule TTP_XOR_QUAD_CurrentVersionRun_ced5 {
  strings:
    $key_ced5 = { 9d ba [2] b9 b4 [2] 92 98 [2] bc ba [2] a8 a1 [2] a7 bb [2] b9 a6 [2] bb a7 [2] a0 a1 [2] bc a6 [2] a0 89 }

  condition:
    any of them
}