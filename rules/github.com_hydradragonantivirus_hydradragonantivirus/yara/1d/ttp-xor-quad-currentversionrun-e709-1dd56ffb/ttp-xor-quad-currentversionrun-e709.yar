rule TTP_XOR_QUAD_CurrentVersionRun_e709 {
  strings:
    $key_e709 = { b4 66 [2] 90 68 [2] bb 44 [2] 95 66 [2] 81 7d [2] 8e 67 [2] 90 7a [2] 92 7b [2] 89 7d [2] 95 7a [2] 89 55 }

  condition:
    any of them
}