rule TTP_XOR_QUAD_CurrentVersionRun_fcf4 {
  strings:
    $key_fcf4 = { af 9b [2] 8b 95 [2] a0 b9 [2] 8e 9b [2] 9a 80 [2] 95 9a [2] 8b 87 [2] 89 86 [2] 92 80 [2] 8e 87 [2] 92 a8 }

  condition:
    any of them
}