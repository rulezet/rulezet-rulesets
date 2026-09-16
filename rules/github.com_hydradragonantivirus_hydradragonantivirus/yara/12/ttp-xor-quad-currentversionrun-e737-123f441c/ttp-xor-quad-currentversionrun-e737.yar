rule TTP_XOR_QUAD_CurrentVersionRun_e737 {
  strings:
    $key_e737 = { b4 58 [2] 90 56 [2] bb 7a [2] 95 58 [2] 81 43 [2] 8e 59 [2] 90 44 [2] 92 45 [2] 89 43 [2] 95 44 [2] 89 6b }

  condition:
    any of them
}