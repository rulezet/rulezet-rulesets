rule TTP_XOR_QUAD_CurrentVersionRun_fc78 {
  strings:
    $key_fc78 = { af 17 [2] 8b 19 [2] a0 35 [2] 8e 17 [2] 9a 0c [2] 95 16 [2] 8b 0b [2] 89 0a [2] 92 0c [2] 8e 0b [2] 92 24 }

  condition:
    any of them
}