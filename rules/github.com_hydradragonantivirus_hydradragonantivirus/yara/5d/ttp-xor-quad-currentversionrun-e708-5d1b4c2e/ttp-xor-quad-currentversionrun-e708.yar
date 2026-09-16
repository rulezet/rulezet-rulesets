rule TTP_XOR_QUAD_CurrentVersionRun_e708 {
  strings:
    $key_e708 = { b4 67 [2] 90 69 [2] bb 45 [2] 95 67 [2] 81 7c [2] 8e 66 [2] 90 7b [2] 92 7a [2] 89 7c [2] 95 7b [2] 89 54 }

  condition:
    any of them
}