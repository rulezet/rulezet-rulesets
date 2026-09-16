rule TTP_XOR_QUAD_CurrentVersionRun_eff4 {
  strings:
    $key_eff4 = { bc 9b [2] 98 95 [2] b3 b9 [2] 9d 9b [2] 89 80 [2] 86 9a [2] 98 87 [2] 9a 86 [2] 81 80 [2] 9d 87 [2] 81 a8 }

  condition:
    any of them
}