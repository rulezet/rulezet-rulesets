rule TTP_XOR_QUAD_CurrentVersionRun_fc0b {
  strings:
    $key_fc0b = { af 64 [2] 8b 6a [2] a0 46 [2] 8e 64 [2] 9a 7f [2] 95 65 [2] 8b 78 [2] 89 79 [2] 92 7f [2] 8e 78 [2] 92 57 }

  condition:
    any of them
}