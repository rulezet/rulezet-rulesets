rule TTP_XOR_QUAD_CurrentVersionRun_fc7a {
  strings:
    $key_fc7a = { af 15 [2] 8b 1b [2] a0 37 [2] 8e 15 [2] 9a 0e [2] 95 14 [2] 8b 09 [2] 89 08 [2] 92 0e [2] 8e 09 [2] 92 26 }

  condition:
    any of them
}