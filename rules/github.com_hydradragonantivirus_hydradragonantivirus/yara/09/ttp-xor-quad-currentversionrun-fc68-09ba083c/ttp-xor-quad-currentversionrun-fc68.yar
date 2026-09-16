rule TTP_XOR_QUAD_CurrentVersionRun_fc68 {
  strings:
    $key_fc68 = { af 07 [2] 8b 09 [2] a0 25 [2] 8e 07 [2] 9a 1c [2] 95 06 [2] 8b 1b [2] 89 1a [2] 92 1c [2] 8e 1b [2] 92 34 }

  condition:
    any of them
}