rule TTP_XOR_QUAD_CurrentVersionRun_fc64 {
  strings:
    $key_fc64 = { af 0b [2] 8b 05 [2] a0 29 [2] 8e 0b [2] 9a 10 [2] 95 0a [2] 8b 17 [2] 89 16 [2] 92 10 [2] 8e 17 [2] 92 38 }

  condition:
    any of them
}