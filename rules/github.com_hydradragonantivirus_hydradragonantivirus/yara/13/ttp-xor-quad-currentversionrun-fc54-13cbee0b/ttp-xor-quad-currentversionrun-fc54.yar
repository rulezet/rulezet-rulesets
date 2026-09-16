rule TTP_XOR_QUAD_CurrentVersionRun_fc54 {
  strings:
    $key_fc54 = { af 3b [2] 8b 35 [2] a0 19 [2] 8e 3b [2] 9a 20 [2] 95 3a [2] 8b 27 [2] 89 26 [2] 92 20 [2] 8e 27 [2] 92 08 }

  condition:
    any of them
}