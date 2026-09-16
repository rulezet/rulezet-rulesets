rule TTP_XOR_QUAD_CurrentVersionRun_fc7d {
  strings:
    $key_fc7d = { af 12 [2] 8b 1c [2] a0 30 [2] 8e 12 [2] 9a 09 [2] 95 13 [2] 8b 0e [2] 89 0f [2] 92 09 [2] 8e 0e [2] 92 21 }

  condition:
    any of them
}