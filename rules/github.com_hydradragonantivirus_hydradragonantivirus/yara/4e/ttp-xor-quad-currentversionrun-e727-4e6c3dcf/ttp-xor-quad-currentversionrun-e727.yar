rule TTP_XOR_QUAD_CurrentVersionRun_e727 {
  strings:
    $key_e727 = { b4 48 [2] 90 46 [2] bb 6a [2] 95 48 [2] 81 53 [2] 8e 49 [2] 90 54 [2] 92 55 [2] 89 53 [2] 95 54 [2] 89 7b }

  condition:
    any of them
}