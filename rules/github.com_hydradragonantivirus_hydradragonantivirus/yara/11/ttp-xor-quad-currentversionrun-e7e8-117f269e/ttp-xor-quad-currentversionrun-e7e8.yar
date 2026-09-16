rule TTP_XOR_QUAD_CurrentVersionRun_e7e8 {
  strings:
    $key_e7e8 = { b4 87 [2] 90 89 [2] bb a5 [2] 95 87 [2] 81 9c [2] 8e 86 [2] 90 9b [2] 92 9a [2] 89 9c [2] 95 9b [2] 89 b4 }

  condition:
    any of them
}