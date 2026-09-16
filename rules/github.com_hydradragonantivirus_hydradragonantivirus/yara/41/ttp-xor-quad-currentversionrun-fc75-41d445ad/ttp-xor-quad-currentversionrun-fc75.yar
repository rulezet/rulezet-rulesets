rule TTP_XOR_QUAD_CurrentVersionRun_fc75 {
  strings:
    $key_fc75 = { af 1a [2] 8b 14 [2] a0 38 [2] 8e 1a [2] 9a 01 [2] 95 1b [2] 8b 06 [2] 89 07 [2] 92 01 [2] 8e 06 [2] 92 29 }

  condition:
    any of them
}