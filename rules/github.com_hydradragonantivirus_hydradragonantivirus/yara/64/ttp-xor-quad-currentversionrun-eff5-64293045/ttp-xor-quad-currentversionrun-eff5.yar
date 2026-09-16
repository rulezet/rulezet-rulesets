rule TTP_XOR_QUAD_CurrentVersionRun_eff5 {
  strings:
    $key_eff5 = { bc 9a [2] 98 94 [2] b3 b8 [2] 9d 9a [2] 89 81 [2] 86 9b [2] 98 86 [2] 9a 87 [2] 81 81 [2] 9d 86 [2] 81 a9 }

  condition:
    any of them
}