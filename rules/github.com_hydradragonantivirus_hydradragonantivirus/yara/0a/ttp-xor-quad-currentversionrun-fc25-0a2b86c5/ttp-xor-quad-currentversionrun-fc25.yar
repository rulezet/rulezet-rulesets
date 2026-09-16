rule TTP_XOR_QUAD_CurrentVersionRun_fc25 {
  strings:
    $key_fc25 = { af 4a [2] 8b 44 [2] a0 68 [2] 8e 4a [2] 9a 51 [2] 95 4b [2] 8b 56 [2] 89 57 [2] 92 51 [2] 8e 56 [2] 92 79 }

  condition:
    any of them
}