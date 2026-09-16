rule TTP_XOR_QUAD_CurrentVersionRun_fc45 {
  strings:
    $key_fc45 = { af 2a [2] 8b 24 [2] a0 08 [2] 8e 2a [2] 9a 31 [2] 95 2b [2] 8b 36 [2] 89 37 [2] 92 31 [2] 8e 36 [2] 92 19 }

  condition:
    any of them
}