rule TTP_XOR_QUAD_CurrentVersionRun_fc47 {
  strings:
    $key_fc47 = { af 28 [2] 8b 26 [2] a0 0a [2] 8e 28 [2] 9a 33 [2] 95 29 [2] 8b 34 [2] 89 35 [2] 92 33 [2] 8e 34 [2] 92 1b }

  condition:
    any of them
}