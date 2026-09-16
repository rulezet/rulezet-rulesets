rule TTP_XOR_QUAD_CurrentVersionRun_fc7b {
  strings:
    $key_fc7b = { af 14 [2] 8b 1a [2] a0 36 [2] 8e 14 [2] 9a 0f [2] 95 15 [2] 8b 08 [2] 89 09 [2] 92 0f [2] 8e 08 [2] 92 27 }

  condition:
    any of them
}