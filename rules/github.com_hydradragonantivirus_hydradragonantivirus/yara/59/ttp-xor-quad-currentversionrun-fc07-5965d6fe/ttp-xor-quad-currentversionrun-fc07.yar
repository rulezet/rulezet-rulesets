rule TTP_XOR_QUAD_CurrentVersionRun_fc07 {
  strings:
    $key_fc07 = { af 68 [2] 8b 66 [2] a0 4a [2] 8e 68 [2] 9a 73 [2] 95 69 [2] 8b 74 [2] 89 75 [2] 92 73 [2] 8e 74 [2] 92 5b }

  condition:
    any of them
}