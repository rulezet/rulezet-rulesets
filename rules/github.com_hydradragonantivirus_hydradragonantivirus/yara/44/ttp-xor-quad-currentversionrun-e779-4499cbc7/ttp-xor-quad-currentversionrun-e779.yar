rule TTP_XOR_QUAD_CurrentVersionRun_e779 {
  strings:
    $key_e779 = { b4 16 [2] 90 18 [2] bb 34 [2] 95 16 [2] 81 0d [2] 8e 17 [2] 90 0a [2] 92 0b [2] 89 0d [2] 95 0a [2] 89 25 }

  condition:
    any of them
}