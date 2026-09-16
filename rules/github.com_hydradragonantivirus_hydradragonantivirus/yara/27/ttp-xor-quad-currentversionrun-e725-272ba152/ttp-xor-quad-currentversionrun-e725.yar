rule TTP_XOR_QUAD_CurrentVersionRun_e725 {
  strings:
    $key_e725 = { b4 4a [2] 90 44 [2] bb 68 [2] 95 4a [2] 81 51 [2] 8e 4b [2] 90 56 [2] 92 57 [2] 89 51 [2] 95 56 [2] 89 79 }

  condition:
    any of them
}