rule TTP_XOR_QUAD_CurrentVersionRun_e718 {
  strings:
    $key_e718 = { b4 77 [2] 90 79 [2] bb 55 [2] 95 77 [2] 81 6c [2] 8e 76 [2] 90 6b [2] 92 6a [2] 89 6c [2] 95 6b [2] 89 44 }

  condition:
    any of them
}