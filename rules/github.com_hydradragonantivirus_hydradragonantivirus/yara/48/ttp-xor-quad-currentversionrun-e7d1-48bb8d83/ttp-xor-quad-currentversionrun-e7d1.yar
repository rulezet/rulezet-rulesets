rule TTP_XOR_QUAD_CurrentVersionRun_e7d1 {
  strings:
    $key_e7d1 = { b4 be [2] 90 b0 [2] bb 9c [2] 95 be [2] 81 a5 [2] 8e bf [2] 90 a2 [2] 92 a3 [2] 89 a5 [2] 95 a2 [2] 89 8d }

  condition:
    any of them
}