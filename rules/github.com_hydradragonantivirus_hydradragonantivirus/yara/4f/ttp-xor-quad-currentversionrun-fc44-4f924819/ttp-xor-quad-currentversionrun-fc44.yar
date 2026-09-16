rule TTP_XOR_QUAD_CurrentVersionRun_fc44 {
  strings:
    $key_fc44 = { af 2b [2] 8b 25 [2] a0 09 [2] 8e 2b [2] 9a 30 [2] 95 2a [2] 8b 37 [2] 89 36 [2] 92 30 [2] 8e 37 [2] 92 18 }

  condition:
    any of them
}