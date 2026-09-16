rule TTP_XOR_QUAD_CurrentVersionRun_eff8 {
  strings:
    $key_eff8 = { bc 97 [2] 98 99 [2] b3 b5 [2] 9d 97 [2] 89 8c [2] 86 96 [2] 98 8b [2] 9a 8a [2] 81 8c [2] 9d 8b [2] 81 a4 }

  condition:
    any of them
}