rule TTP_XOR_QUAD_CurrentVersionRun_fc55 {
  strings:
    $key_fc55 = { af 3a [2] 8b 34 [2] a0 18 [2] 8e 3a [2] 9a 21 [2] 95 3b [2] 8b 26 [2] 89 27 [2] 92 21 [2] 8e 26 [2] 92 09 }

  condition:
    any of them
}