rule TTP_XOR_QUAD_CurrentVersionRun_e7f3 {
  strings:
    $key_e7f3 = { b4 9c [2] 90 92 [2] bb be [2] 95 9c [2] 81 87 [2] 8e 9d [2] 90 80 [2] 92 81 [2] 89 87 [2] 95 80 [2] 89 af }

  condition:
    any of them
}