rule TTP_XOR_QUAD_CurrentVersionRun_fc74 {
  strings:
    $key_fc74 = { af 1b [2] 8b 15 [2] a0 39 [2] 8e 1b [2] 9a 00 [2] 95 1a [2] 8b 07 [2] 89 06 [2] 92 00 [2] 8e 07 [2] 92 28 }

  condition:
    any of them
}