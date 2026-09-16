rule TTP_XOR_QUAD_CurrentVersionRun_fc17 {
  strings:
    $key_fc17 = { af 78 [2] 8b 76 [2] a0 5a [2] 8e 78 [2] 9a 63 [2] 95 79 [2] 8b 64 [2] 89 65 [2] 92 63 [2] 8e 64 [2] 92 4b }

  condition:
    any of them
}