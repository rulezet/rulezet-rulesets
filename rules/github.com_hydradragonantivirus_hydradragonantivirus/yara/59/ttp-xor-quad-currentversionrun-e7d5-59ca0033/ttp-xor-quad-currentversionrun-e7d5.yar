rule TTP_XOR_QUAD_CurrentVersionRun_e7d5 {
  strings:
    $key_e7d5 = { b4 ba [2] 90 b4 [2] bb 98 [2] 95 ba [2] 81 a1 [2] 8e bb [2] 90 a6 [2] 92 a7 [2] 89 a1 [2] 95 a6 [2] 89 89 }

  condition:
    any of them
}